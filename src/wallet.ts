/**
 * 多签钱包策略引擎。
 *
 * 在阈值策略、签名收集、重放防护、FIFO 执行队列、策略变更任务与“任务取消”之上，新增
 * “原子批量普通交易”：submitBatchTransaction 接收有序调用列表（1..64 项，每项含收款地址、
 * 金额、data），以独立域标签 safe-wallet/tx-batch/v1 对钱包标识、nonce、deadline 与按顺序
 * 编码的全部调用整体签名。成功时只入队一个批量任务、只消费本次 nonce；执行时整批生效，
 * 只产生一个 result 为 transfer-batch 的回执（无部分执行），重复执行返回同一任务与回执。
 * 单笔交易、策略变更、取消的签名格式与执行/取消/幂等语义均保持不变。
 */

import {
  type Address,
  ZERO_ADDRESS,
  isZeroAddress,
  normalizeAddress,
  recoverAddress,
} from './crypto.ts';
import {
  hashCancellation,
  hashPolicyChange,
  hashTransaction,
  hashTransactionBatch,
  type PolicyChangeRequest,
  type TransactionRequest,
} from './encoding.ts';
import {
  InvalidCancellation,
  InvalidPolicyChange,
  InvalidTransaction,
  InvalidTransactionBatch,
  NonceAlreadyUsedError,
  RequestExpired,
  PolicyConflict,
  InvalidQueueStateError,
  TaskCancellationConflict,
  TaskNotFoundError,
} from './errors.ts';
import { ExecutionQueue, type QueueTask } from './queue.ts';

// ---------- 任务载荷 ----------

export type WalletTaskPayload =
  | {
      kind: 'transaction';
      deadline: bigint;
      to: Address;
      value: bigint;
      data: Uint8Array;
    }
  | {
      kind: 'transaction-batch';
      deadline: bigint;
      /** 规范化后的有序调用（地址小写校验位形式；顺序即执行顺序） */
      calls: BatchCall[];
    }
  | {
      kind: 'policy-change';
      deadline: bigint;
      /** 提交时绑定的策略版本；执行时必须仍等于当前版本 */
      version: bigint;
      newOwners: Address[];
      newConfirmations: bigint;
    };

/** 批量任务内部保存的单笔调用（地址已规范化，data 已拷贝为 Buffer） */
export interface BatchCall {
  to: Address;
  value: bigint;
  data: Uint8Array;
}

export type WalletTask = QueueTask<WalletTaskPayload>;

export interface PolicyState {
  owners: Address[];
  confirmations: bigint;
  version: bigint;
}

export interface WalletOptions {
  id: string;
  owners: Address[];
  confirmations: bigint | number;
  /** 注入时钟，返回 Unix 秒；默认取系统时间 */
  now?: () => bigint;
}

export interface TransactionSubmission {
  nonce: bigint | number;
  deadline: bigint | number;
  to: string;
  value: bigint | number;
  data?: Uint8Array;
}

export interface BatchCallSubmission {
  to: string;
  value: bigint | number;
  data?: Uint8Array;
}

export interface BatchTransactionSubmission {
  nonce: bigint | number;
  deadline: bigint | number;
  /** 有序调用列表：非空且至多 MAX_BATCH_CALLS 项，顺序即签名与执行顺序 */
  calls: readonly BatchCallSubmission[];
}

/** 批量交易调用条数上限（含） */
export const MAX_BATCH_CALLS = 64;

export interface PolicyChangeSubmission {
  version: bigint | number;
  nonce: bigint | number;
  deadline: bigint | number;
  newOwners: string[];
  newConfirmations: bigint | number;
}

export interface CancellationSubmission {
  /** 目标任务 id（队列快照中的任务标识） */
  taskId: string;
  nonce: bigint | number;
  deadline: bigint | number;
}

function isNonNegativeInteger(n: bigint, maxBits = 256): boolean {
  return n >= 0n && n < 2n ** BigInt(maxBits);
}

/** 安全标量转换：非法输入（undefined / 字符串等）归一为指定的 Invalid* 错误 */
function toBigInt(value: unknown, Invalid: new (msg: string) => Error, field: string): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return BigInt(value.trim());
  throw new Invalid(`field "${field}" must be a non-negative integer`);
}

export class MultiSigWallet {
  readonly id: string;
  private readonly now: () => bigint;

  private owners: Address[];
  private readonly ownerSet: Set<Address>;
  private confirmations: bigint;
  private version: bigint;

  /** 下一个期望 nonce（严格递增，顺序提交） */
  private nextNonce = 0n;
  /** 已消费 nonce（入队即消费；失败终态也不释放） */
  private readonly usedNonces = new Set<bigint>();

  readonly queue: ExecutionQueue<WalletTaskPayload>;

  constructor(opts: WalletOptions) {
    const owners = normalizeOwnerList(opts.owners);
    const confirmations = BigInt(opts.confirmations);
    if (confirmations <= 0n || confirmations > BigInt(owners.length)) {
      throw new InvalidPolicyChange(
        `initial confirmations must be within 1..owners (${owners.length}), got ${confirmations}`,
      );
    }
    this.id = opts.id;
    this.now = opts.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
    this.owners = owners;
    this.ownerSet = new Set(owners);
    this.confirmations = confirmations;
    this.version = 1n;
    this.queue = new ExecutionQueue((task) => this.applyTask(task));
  }

  // ---------- 只读状态 ----------

  get policy(): PolicyState {
    return { owners: [...this.owners], confirmations: this.confirmations, version: this.version };
  }

  get policyVersion(): bigint {
    return this.version;
  }

  get currentOwners(): Address[] {
    return [...this.owners];
  }

  get requiredConfirmations(): bigint {
    return this.confirmations;
  }

  get expectedNonce(): bigint {
    return this.nextNonce;
  }

  isOwner(address: string): boolean {
    const a = normalizeAddress(address);
    return a !== null && this.ownerSet.has(a);
  }

  isNonceUsed(nonce: bigint | number): boolean {
    return this.usedNonces.has(BigInt(nonce));
  }

  get tasks(): readonly WalletTask[] {
    return this.queue.listTasks();
  }

  // ---------- 普通交易提交（行为与既有流程一致，载荷不含策略版本） ----------

  submitTransaction(sub: TransactionSubmission, signatures: readonly Uint8Array[]): WalletTask {
    // 原始值透传，由 submit 统一做安全转换，避免在入口抛出原生 TypeError
    return this.submit(
      'transaction',
      {
        nonce: sub.nonce,
        deadline: sub.deadline,
        to: sub.to,
        value: sub.value,
        data: sub.data ?? new Uint8Array(),
      },
      signatures,
    );
  }

  // ---------- 原子批量普通交易提交 ----------

  /**
   * 提交一笔原子批量普通交易：有序调用列表整体签名、整体入队、整体执行。
   *
   * 摘要使用独立域标签 safe-wallet/tx-batch/v1（不含策略版本），绑定钱包标识、nonce、
   * deadline 与按顺序编码的全部调用；普通交易、策略变更、取消签名均不能授权批量交易，
   * 任一调用内容或顺序变化都会改变摘要。
   *
   * 校验顺序（与既有提交流程一致；任一失败都不建任务、不消费 nonce、不改策略/队列）：
   *   1) nonce 复用 → NonceAlreadyUsedError
   *   2) deadline 早于当前时间 → RequestExpired
   *   3) nonce 顺序 / 调用列表 / 字段 / 签名 → InvalidTransactionBatch
   *
   * 成功时只入队一个 transaction-batch 任务、只消费本次 nonce 并推进 expectedNonce。
   */
  submitBatchTransaction(
    sub: BatchTransactionSubmission,
    signatures: readonly Uint8Array[],
  ): WalletTask {
    const Invalid = InvalidTransactionBatch;

    // (1) nonce 复用优先于过期判定（旧请求重放恒得此异常，即使已过期）
    const nonce = toBigInt(sub.nonce, Invalid, 'nonce');
    if (!isNonNegativeInteger(nonce)) throw new Invalid('nonce must be a non-negative integer');
    if (this.usedNonces.has(nonce)) throw new NonceAlreadyUsedError(nonce);

    // (2) 截止时间
    const deadline = toBigInt(sub.deadline, Invalid, 'deadline');
    if (!isNonNegativeInteger(deadline)) throw new Invalid('deadline out of range');
    if (deadline < this.now()) {
      throw new RequestExpired(`request deadline ${deadline} already passed`);
    }
    if (nonce !== this.nextNonce) {
      throw new Invalid(`expected nonce ${this.nextNonce}, got ${nonce}`);
    }

    // (3) 调用列表：必须是非空数组且不超过上限；逐项规范化，顺序保持不变
    const calls = this.normalizeBatchCalls(sub.calls);

    // (4) 阈值签名：摘要绑定钱包标识、nonce、deadline、按顺序编码的全部调用
    const digest = hashTransactionBatch({
      walletId: this.id,
      nonce,
      deadline,
      calls,
    });
    this.verifyThresholdSignatures(digest, signatures, Invalid);

    // (5) 原子生效：只入队一个批量任务 + 只消费本次 nonce
    let task: WalletTask;
    try {
      task = this.queue.enqueue({
        nonce,
        digest: digest.toString('hex'),
        payload: { kind: 'transaction-batch', deadline, calls },
        submittedAt: this.now(),
      });
    } catch (err) {
      if (err instanceof InvalidQueueStateError) throw new Invalid(err.message);
      throw err;
    }
    this.usedNonces.add(nonce);
    this.nextNonce = nonce + 1n;
    return task;
  }

  // ---------- 策略变更提交 ----------

  proposePolicyChange(sub: PolicyChangeSubmission, signatures: readonly Uint8Array[]): WalletTask {
    return this.submit(
      'policy-change',
      {
        version: sub.version,
        nonce: sub.nonce,
        deadline: sub.deadline,
        newOwners: sub.newOwners,
        newConfirmations: sub.newConfirmations,
      },
      signatures,
    );
  }

  // ---------- 任务取消 ----------

  /**
   * 取消一个尚未执行的 queued 任务。
   *
   * 取消摘要使用 safe-wallet/cancel/v1 域标签，绑定钱包标识、目标任务 digest、nonce 与
   * 截止时间：签名无法改绑其他任务、其他钱包或其他时间窗口。
   *
   * 校验顺序（任一失败都不改变任务、不消费 nonce、不改变策略）：
   *   1) 字段非法 → InvalidCancellation
   *   2) nonce 复用 → NonceAlreadyUsedError（旧请求重放恒得此异常，即使已过期）
   *   3) deadline 早于当前时间 → RequestExpired
   *   4) nonce 顺序（须等于 expectedNonce）→ InvalidCancellation
   *   5) 目标不存在 → TaskNotFoundError；目标已终态 → TaskCancellationConflict
   *   6) 阈值签名（当前所有者、去重后达到当前确认数）→ InvalidCancellation
   *
   * 成功时目标任务由 queued 进入 cancelled 终态并返回：保留原 payload/digest/nonce，
   * 记录取消时间与取消摘要；不执行目标效果，不改变 owners/确认数/策略版本，
   * 只消费本次 nonce 并推进 expectedNonce。取消不要求任务在队首，也不调整队列顺序。
   */
  cancelTask(
    taskId: string,
    nonce: bigint | number,
    deadline: bigint | number,
    signatures: readonly Uint8Array[],
  ): WalletTask;
  cancelTask(sub: CancellationSubmission, signatures: readonly Uint8Array[]): WalletTask;
  cancelTask(
    a: string | CancellationSubmission,
    b: readonly Uint8Array[] | bigint | number,
    c?: bigint | number,
    d?: readonly Uint8Array[],
  ): WalletTask {
    const sub: CancellationSubmission =
      typeof a === 'string' || a === undefined || a === null
        ? { taskId: a as string, nonce: b as bigint | number, deadline: c as bigint | number }
        : a;
    const signatures: readonly Uint8Array[] =
      (typeof a === 'string' || a === undefined || a === null ? d : (b as readonly Uint8Array[])) ??
      ([] as readonly Uint8Array[]);

    // (1) 字段安全转换（畸形输入只抛 InvalidCancellation）
    const nonce = toBigInt(sub.nonce, InvalidCancellation, 'nonce');
    if (!isNonNegativeInteger(nonce)) {
      throw new InvalidCancellation('nonce must be a non-negative integer');
    }
    // (2) nonce 复用优先于过期判定
    if (this.usedNonces.has(nonce)) throw new NonceAlreadyUsedError(nonce);

    const deadline = toBigInt(sub.deadline, InvalidCancellation, 'deadline');
    if (!isNonNegativeInteger(deadline)) throw new InvalidCancellation('deadline out of range');
    // (3) 截止时间
    if (deadline < this.now()) {
      throw new RequestExpired(`request deadline ${deadline} already passed`);
    }
    // (4) nonce 顺序：取消与提交共用同一严格递增序列
    if (nonce !== this.nextNonce) {
      throw new InvalidCancellation(`expected nonce ${this.nextNonce}, got ${nonce}`);
    }

    // (5) 目标任务状态
    const taskId = sub.taskId;
    if (typeof taskId !== 'string' || taskId.length === 0) {
      throw new InvalidCancellation('taskId must be a non-empty string');
    }
    const target = this.queue.getTask(taskId);
    if (target === null) throw new TaskNotFoundError(`task not found: ${taskId}`);
    if (target.status !== 'queued') {
      throw new TaskCancellationConflict(`task ${taskId} is already ${target.status}`);
    }

    // (6) 阈值签名：摘要绑定钱包标识、目标任务 digest、nonce、deadline
    const digest = hashCancellation({
      walletId: this.id,
      taskDigest: target.digest,
      nonce,
      deadline,
    });
    this.verifyThresholdSignatures(digest, signatures, InvalidCancellation);

    // 原子生效：目标任务进入 cancelled 终态 + 消费 nonce；策略与队列顺序不变
    const cancelled = this.queue.cancel(taskId, this.now(), digest.toString('hex'));
    this.usedNonces.add(nonce);
    this.nextNonce = nonce + 1n;
    return cancelled;
  }

  // ---------- 执行 ----------

  executeTask(taskId: string): WalletTask {
    return this.queue.execute(taskId, this.now());
  }

  executeNext(): WalletTask | null {
    return this.queue.executeNext(this.now());
  }

  getTask(taskId: string): WalletTask | null {
    return this.queue.getTask(taskId);
  }

  // ============================================================
  // 内部实现
  // ============================================================

  /**
   * 统一提交入口。raw 接收未经转换的原始标量（bigint/number/string），
   * 所有转换与字段合法性判定都在这里完成，保证只能抛出约定错误类型。
   */
  private submit(
    kind: WalletTaskPayload['kind'],
    raw: Record<string, unknown>,
    signatures: readonly Uint8Array[],
  ): WalletTask {
    const Invalid = kind === 'policy-change' ? InvalidPolicyChange : InvalidTransaction;

    // 校验优先级（任一失败都不建任务、不消费 nonce、不改策略）：
    //   1) nonce 复用 → 既有重放防护的公开异常（旧请求重放即使已过期也仍报复用）
    //   2) 截止时间早于当前时间 → RequestExpired
    //   3) 字段 / 版本 / nonce 顺序 / 签名 → 对应 Invalid*
    const nonce = toBigInt(raw.nonce, Invalid, 'nonce');
    if (!isNonNegativeInteger(nonce)) throw new Invalid('nonce must be a non-negative integer');
    if (this.usedNonces.has(nonce)) throw new NonceAlreadyUsedError(nonce);

    const deadline = toBigInt(raw.deadline, Invalid, 'deadline');
    if (!isNonNegativeInteger(deadline)) throw new Invalid('deadline out of range');
    if (deadline < this.now()) {
      throw new RequestExpired(`request deadline ${deadline} already passed`);
    }
    if (nonce !== this.nextNonce) throw new Invalid(`expected nonce ${this.nextNonce}, got ${nonce}`);

    // (3) 字段校验 + 规范化
    let payload: WalletTaskPayload;
    let digest: Buffer;
    if (kind === 'transaction') {
      const to = normalizeAddress(raw.to as string);
      if (to === null || isZeroAddress(to)) throw new Invalid('invalid or zero recipient address');
      const value = toBigInt(raw.value, Invalid, 'value');
      if (!isNonNegativeInteger(value)) throw new Invalid('value out of range');
      const dataField = raw.data;
      if (
        dataField !== undefined &&
        !(dataField instanceof Uint8Array) &&
        !ArrayBuffer.isView(dataField)
      ) {
        throw new Invalid('data must be a byte array');
      }
      const data = Buffer.from((dataField as Uint8Array | undefined) ?? new Uint8Array());
      const req: TransactionRequest = {
        walletId: this.id,
        nonce,
        deadline,
        to,
        value,
        data,
      };
      digest = hashTransaction(req);
      payload = { kind: 'transaction', deadline, to, value, data };
    } else {
      const version = toBigInt(raw.version, InvalidPolicyChange, 'version');
      // (3a) 版本必须绑定当前版本（提交时不匹配 → InvalidPolicyChange；执行时漂移 → PolicyConflict）
      if (version !== this.version) {
        throw new InvalidPolicyChange(
          `policy version mismatch: bound ${version}, current ${this.version}`,
        );
      }
      // (3b) 以当前版本为基准验证新策略
      const newOwners = normalizeOwnerList(raw.newOwners as string[], InvalidPolicyChange);
      const newConfirmations = toBigInt(raw.newConfirmations, InvalidPolicyChange, 'newConfirmations');
      if (newConfirmations <= 0n || newConfirmations > BigInt(newOwners.length)) {
        throw new InvalidPolicyChange(
          `new confirmations must be within 1..new owners (${newOwners.length}), got ${newConfirmations}`,
        );
      }
      const req: PolicyChangeRequest = {
        walletId: this.id,
        version,
        nonce,
        deadline,
        newOwners,
        newConfirmations,
      };
      digest = hashPolicyChange(req);
      payload = { kind: 'policy-change', deadline, version, newOwners, newConfirmations };
    }

    // (4) 阈值签名：恢复 → 去重 → 必须为当前所有者 → 数量达到当前确认数
    this.verifyThresholdSignatures(digest, signatures, Invalid);

    // (5) 原子生效（到队列为止）：入队 + 消费 nonce。
    //     入队失败（同一摘要重复等）时不消费 nonce。
    let task: WalletTask;
    try {
      task = this.queue.enqueue({
        nonce,
        digest: digest.toString('hex'),
        payload,
        submittedAt: this.now(),
      });
    } catch (err) {
      if (err instanceof InvalidQueueStateError) throw new Invalid(err.message);
      throw err;
    }
    this.usedNonces.add(nonce);
    this.nextNonce = nonce + 1n;
    return task;
  }

  /**
   * 规范化批量调用列表：列表非空且至多 MAX_BATCH_CALLS 项；每项的收款地址合法且非零、
   * 金额为非负 256 位整数、data 为字节数组（缺省为空）。顺序原样保留，不做去重/排序。
   */
  private normalizeBatchCalls(rawCalls: unknown): BatchCall[] {
    if (!Array.isArray(rawCalls)) {
      throw new InvalidTransactionBatch('calls must be a non-empty array');
    }
    if (rawCalls.length === 0) {
      throw new InvalidTransactionBatch('calls list must not be empty');
    }
    if (rawCalls.length > MAX_BATCH_CALLS) {
      throw new InvalidTransactionBatch(
        `calls list exceeds the limit of ${MAX_BATCH_CALLS}, got ${rawCalls.length}`,
      );
    }
    const calls: BatchCall[] = [];
    for (const rawCall of rawCalls) {
      if (rawCall === null || typeof rawCall !== 'object') {
        throw new InvalidTransactionBatch('each call must be an object with to/value/data');
      }
      const call = rawCall as Record<string, unknown>;
      const to = normalizeAddress(call.to as string);
      if (to === null || isZeroAddress(to)) {
        throw new InvalidTransactionBatch('invalid or zero recipient address in batch call');
      }
      const value = toBigInt(call.value, InvalidTransactionBatch, 'value');
      if (!isNonNegativeInteger(value)) {
        throw new InvalidTransactionBatch('value out of range in batch call');
      }
      const dataField = call.data;
      if (
        dataField !== undefined &&
        !(dataField instanceof Uint8Array) &&
        !ArrayBuffer.isView(dataField)
      ) {
        throw new InvalidTransactionBatch('data must be a byte array in batch call');
      }
      const data = Buffer.from((dataField as Uint8Array | undefined) ?? new Uint8Array());
      calls.push({ to, value, data });
    }
    return calls;
  }

  /** 按“当前策略”的所有者集合与确认数校验签名收集 */  private verifyThresholdSignatures(
    digest: Uint8Array,
    signatures: readonly Uint8Array[],
    Invalid: new (msg: string) => Error,
  ): void {
    if (!Array.isArray(signatures)) {
      throw new Invalid('signatures must be an array');
    }
    if (signatures.length === 0) throw new Invalid('missing signatures');

    const signedBy = new Set<Address>();
    for (const sig of signatures) {
      if (!(sig instanceof Uint8Array) || sig.length !== 65) {
        throw new Invalid('each signature must be a 65-byte r||s||v blob');
      }
      const signer = recoverAddress(digest, Uint8Array.from(sig));
      if (signer === null) throw new Invalid('malformed or non-canonical signature');
      if (!this.ownerSet.has(signer)) {
        // 非所有者签名：既可能是伪造，也可能是签名载荷与提交内容不匹配
        throw new Invalid('signature does not match payload or signer is not an owner');
      }
      signedBy.add(signer); // 地址去重：同一所有者多签只计一次
    }
    if (BigInt(signedBy.size) < this.confirmations) {
      throw new Invalid(
        `threshold not met: need ${this.confirmations} distinct owners, got ${signedBy.size}`,
      );
    }
  }

  /** 队列执行器回调：定义各类任务的生效语义 */
  private applyTask(task: WalletTask): unknown {
    const p = task.payload;
    if (p.kind === 'transaction') {
      // 普通交易既有执行结果：一个可观察的执行产物；不触碰策略状态。
      // 截止时间只在提交阶段核对（RequestExpired），不作为执行闸门，以保持既有执行结果不变。
      return {
        kind: 'transfer',
        to: p.to,
        value: p.value,
        data: Buffer.from(p.data).toString('hex'),
      };
    }

    if (p.kind === 'transaction-batch') {
      // 原子批量：整批只产生一个回执，calls 按输入顺序给出规范化地址、原金额与十六进制 data。
      // 本引擎不产生部分执行回执：回调内不做部分生效，任何失败都按既有失败终态处理整批。
      // 与普通交易一致：不触碰策略状态；deadline 不是执行闸门。
      return {
        kind: 'transfer-batch',
        calls: p.calls.map((call) => ({
          to: call.to,
          value: call.value,
          data: Buffer.from(call.data).toString('hex'),
        })),
      };
    }

    // 策略变更：仅当绑定版本仍等于当前版本时生效
    if (p.version !== this.version) {
      throw new PolicyConflict(
        `policy version drifted: task bound ${p.version}, current ${this.version}`,
      );
    }
    // 所有者集合与确认数同时替换；版本恰好递增一次
    this.owners = [...p.newOwners];
    this.ownerSet.clear();
    for (const o of this.owners) this.ownerSet.add(o);
    this.confirmations = p.newConfirmations;
    this.version += 1n;
    return {
      kind: 'policy-applied',
      version: this.version,
      owners: [...this.owners],
      confirmations: this.confirmations,
    };
  }
}

// ---------- 所有者列表规范化（空/重复/零地址校验） ----------

function normalizeOwnerList(
  input: readonly string[],
  ErrorCtor: typeof InvalidPolicyChange | typeof InvalidTransaction = InvalidPolicyChange,
): Address[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new ErrorCtor('owners list must be a non-empty array');
  }
  const out: Address[] = [];
  const seen = new Set<Address>();
  for (const raw of input) {
    const addr = normalizeAddress(raw);
    if (addr === null) throw new ErrorCtor(`invalid owner address: ${String(raw)}`);
    if (addr === ZERO_ADDRESS || isZeroAddress(addr)) {
      throw new ErrorCtor('zero address is not allowed as owner');
    }
    if (seen.has(addr)) throw new ErrorCtor(`duplicate owner: ${addr}`);
    seen.add(addr);
    out.push(addr);
  }
  return out;
}
