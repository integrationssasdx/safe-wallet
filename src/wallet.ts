/**
 * 多签钱包策略引擎。
 *
 * 在阈值策略、签名收集、重放防护、FIFO 执行队列、策略变更任务、任务取消与原子批量之上，
 * 新增“普通交易分阶段签名收集（审批）”：createTransactionApproval 只登记交易内容与
 * 创建时策略版本（safe-wallet/tx-approval/v1 域摘要），不消费 nonce、不入队、不建任务；
 * 所有者可逐个 addApprovalSignature 加签，达到当前阈值后由 submitApprovedTransaction
 * 按既有 safe-wallet/tx/v1 摘要入队，仅在此时消费创建时预留的 nonce。
 * 审批摘要与普通交易摘要域分隔、互不通用；旧的一次性提交入口行为保持不变。
 */

import { createHash } from 'node:crypto';
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
  hashTransactionApproval,
  hashTransactionBatch,
  type PolicyChangeRequest,
  type TransactionBatchRequest,
  type TransactionRequest,
} from './encoding.ts';
import {
  ApprovalAlreadySubmittedError,
  ApprovalExpiredError,
  ApprovalNotFoundError,
  ApprovalNonceConflictError,
  ApprovalPolicyConflictError,
  ApprovalThresholdNotMetError,
  DuplicateApprovalSignatureError,
  InvalidApprovalSignatureError,
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
      /** 有序调用；顺序即执行顺序，执行回执按同一顺序给出 */
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

/** 批量任务内的单次调用（规范化后的收款地址、原金额、原始 data 副本） */
export interface BatchCall {
  to: Address;
  value: bigint;
  data: Uint8Array;
}

export type WalletTask = QueueTask<WalletTaskPayload>;

/**
 * 审批内部记录（不导出）：登记审批摘要（tx-approval 域）、提交时使用的普通交易摘要
 * （tx 域）、创建时版本/nonce/阈值快照，以及按加签顺序去重收集的签名者。
 * 创建不消费 nonce、不入队；submitted 仅在 submitApprovedTransaction 成功入队后置位。
 */
interface ApprovalRecord {
  id: string;
  /** safe-wallet/tx-approval/v1 摘要 */
  approvalDigest: Buffer;
  /** safe-wallet/tx/v1 摘要（hex）；提交入队时作为任务 digest */
  txDigest: string;
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  /** 创建时确认数快照 */
  confirmations: bigint;
  to: Address;
  value: bigint;
  data: Buffer;
  /** 按加签先后顺序排列的去重签名者（加入时均为当前所有者） */
  signers: Address[];
  submitted: boolean;
  /** 提交入队后的任务 id；仅 submitted 时存在 */
  taskId?: string;
  createdAt: bigint;
}

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

/** 批量提交中的单次调用（原始输入；地址在校验时规范化） */
export interface BatchCallSubmission {
  to: string;
  value: bigint | number;
  /** 必含的调用数据（允许零长度）；必须是 Uint8Array */
  data: Uint8Array;
}

export interface BatchTransactionSubmission {
  nonce: bigint | number;
  deadline: bigint | number;
  /** 有序调用列表：非空且最多 MAX_BATCH_CALLS 项，顺序参与签名且不得改变 */
  calls: readonly BatchCallSubmission[];
}

/** 批量交易调用数量上限（含） */
export const MAX_BATCH_CALLS = 64;

// ---------- 普通交易分阶段签名收集（审批） ----------

/** 创建审批的入参：字段与普通交易提交一致（策略版本在创建时自动绑定，不由调用方提供） */
export type TransactionApprovalSubmission = TransactionSubmission;

/**
 * 审批生命周期：
 *   collecting  —— 已登记，去重签名者尚不足当前确认数（可加签）
 *   ready       —— 去重签名者已达到当前确认数（仍可继续由其他所有者加签，可提交）
 *   expired     —— 查询时刻已过截止时间（终态：不可加签 / 提交；过期优先于版本漂移）
 *   conflicted  —— 未过期但当前策略版本已不同于创建时版本（终态：不可加签 / 提交）
 *   submitted   —— 已由 submitApprovedTransaction 入队（终态：不可加签 / 重复提交）
 */
export type TransactionApprovalStatus =
  | 'collecting'
  | 'ready'
  | 'expired'
  | 'conflicted'
  | 'submitted';

export interface TransactionApproval {
  /** 审批标识（引擎内唯一、可复现地由审批摘要派生） */
  id: string;
  /** safe-wallet/tx-approval/v1 域的签名摘要（hex） */
  digest: string;
  /** 创建时绑定的策略版本 */
  version: bigint;
  /** 提交时将消费的 nonce（创建时不消费） */
  nonce: bigint;
  deadline: bigint;
  /** 创建时达到阈值所需的确认数快照（信息性） */
  confirmations: bigint;
  to: Address;
  value: bigint;
  data: Uint8Array;
  /** 已加签的当前所有者地址，按加签先后顺序排列（去重） */
  signers: Address[];
  status: TransactionApprovalStatus;
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

  /** 已登记的普通交易审批（按 id 索引）；创建不消费 nonce、不入队 */
  private readonly approvals = new Map<string, ApprovalRecord>();

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
   * 提交一个有序调用列表作为单个原子批量任务。
   *
   * 摘要使用 safe-wallet/tx-batch/v1 域标签，绑定钱包标识、nonce、截止时间与按顺序编码的
   * 全部调用：单笔交易 / 策略变更 / 取消签名都不能授权批量交易；任一调用的收款方、金额、
   * data 或调用顺序、项数变化都会改变摘要。
   *
   * 校验顺序与单笔提交一致（任一失败都不建任务、不消费 nonce、不改策略/队列）：
   *   1) nonce 复用 → NonceAlreadyUsedError（旧请求重放恒得此异常，即使已过期）
   *   2) deadline 早于当前时间 → RequestExpired
   *   3) 列表（1..64 项）、收款地址、金额、data、nonce 顺序、阈值签名 → InvalidTransactionBatch
   *
   * 成功时只入队一个批量任务、只消费本次 nonce 并推进 expectedNonce。
   */
  submitBatchTransaction(sub: BatchTransactionSubmission, signatures: readonly Uint8Array[]): WalletTask {
    return this.submit(
      'transaction-batch',
      {
        nonce: sub.nonce,
        deadline: sub.deadline,
        calls: sub.calls,
      },
      signatures,
    );
  }

  // ---------- 普通交易分阶段签名收集（审批） ----------

  /**
   * 登记一个普通交易审批：校验字段与 nonce 顺序，记录创建时策略版本下的
   * safe-wallet/tx-approval/v1 摘要；不消费 nonce、不入队、不建任务、不改策略。
   *
   * 失败约定（与既有提交一致：不消费 nonce、不建任务、不改策略）：
   *   - nonce / deadline / 收款地址 / 金额 / data 非法，或 nonce 跳号（≠ expectedNonce）
   *     → InvalidTransaction
   *   - nonce 已被使用 → NonceAlreadyUsedError（旧请求重放恒得此异常，即使已过期）
   *   - deadline 早于当前时间 → RequestExpired
   */
  createTransactionApproval(sub: TransactionApprovalSubmission): TransactionApproval {
    // 校验优先级与 submit('transaction') 保持一致：
    //   1) nonce 复用 → NonceAlreadyUsedError
    //   2) 截止时间 → RequestExpired
    //   3) 字段 / nonce 顺序 → InvalidTransaction
    const nonce = toBigInt(sub.nonce, InvalidTransaction, 'nonce');
    if (!isNonNegativeInteger(nonce)) throw new InvalidTransaction('nonce must be a non-negative integer');
    if (this.usedNonces.has(nonce)) throw new NonceAlreadyUsedError(nonce);

    const deadline = toBigInt(sub.deadline, InvalidTransaction, 'deadline');
    if (!isNonNegativeInteger(deadline)) throw new InvalidTransaction('deadline out of range');
    if (deadline < this.now()) {
      throw new RequestExpired(`request deadline ${deadline} already passed`);
    }
    if (nonce !== this.nextNonce) {
      throw new InvalidTransaction(`expected nonce ${this.nextNonce}, got ${nonce}`);
    }

    const to = normalizeAddress(sub.to);
    if (to === null || isZeroAddress(to)) throw new InvalidTransaction('invalid or zero recipient address');
    const value = toBigInt(sub.value, InvalidTransaction, 'value');
    if (!isNonNegativeInteger(value)) throw new InvalidTransaction('value out of range');
    const dataField = sub.data;
    if (
      dataField !== undefined &&
      !(dataField instanceof Uint8Array) &&
      !ArrayBuffer.isView(dataField)
    ) {
      throw new InvalidTransaction('data must be a byte array');
    }
    // 复制 data，避免登记后调用方再改动同一缓冲区改变审批内容 / 摘要
    const data = Buffer.from(dataField ?? new Uint8Array());

    const version = this.version;
    const approvalDigest = hashTransactionApproval({
      walletId: this.id,
      version,
      nonce,
      deadline,
      to,
      value,
      data,
    });
    // 提交时沿用既有普通交易摘要（不含版本字段）与任务 payload
    const txDigest = hashTransaction({
      walletId: this.id,
      nonce,
      deadline,
      to,
      value,
      data,
    });

    const id = createHash('sha256')
      .update(`approval:${approvalDigest.toString('hex')}`)
      .digest('hex')
      .slice(0, 16);
    // 同一审批摘要重复登记：幂等返回既有审批（内容与版本承诺完全相同，不产生第二条记录）
    const existing = this.approvals.get(id);
    if (existing !== undefined) return this.toApprovalView(existing);

    const record: ApprovalRecord = {
      id,
      approvalDigest,
      txDigest: txDigest.toString('hex'),
      version,
      nonce,
      deadline,
      confirmations: this.confirmations,
      to,
      value,
      data,
      signers: [],
      submitted: false,
      createdAt: this.now(),
    };
    this.approvals.set(id, record);
    return this.toApprovalView(record);
  }

  /**
   * 对审批追加一个 65 字节签名（r||s||v）：签名摘要必须是创建时的
   * safe-wallet/tx-approval/v1 摘要，恢复出的签名者必须是当前所有者。
   *
   * 错误约定：
   *   - 未知 id → ApprovalNotFoundError
   *   - 已提交 → ApprovalAlreadySubmittedError
   *   - 已过截止时间 → ApprovalExpiredError（过期优先于版本冲突）
   *   - 版本漂移（未过期）→ ApprovalPolicyConflictError
   *   - 同一当前所有者再次加签 → DuplicateApprovalSignatureError
   *   - 签名格式 / 摘要 / 签名者不符（非 65 字节、恢复失败、签名者非当前所有者）
   *     → InvalidApprovalSignatureError
   *
   * 去重后的当前所有者签名数达到当前确认数时状态转为 ready；返回更新后的审批视图。
   */
  addApprovalSignature(approvalId: string, signature: Uint8Array): TransactionApproval {
    const record = this.requireActiveApproval(approvalId);

    if (!(signature instanceof Uint8Array) || signature.length !== 65) {
      throw new InvalidApprovalSignatureError('each signature must be a 65-byte r||s||v blob');
    }
    const signer = recoverAddress(record.approvalDigest, Uint8Array.from(signature));
    if (signer === null) {
      throw new InvalidApprovalSignatureError('malformed or non-canonical signature');
    }
    if (!this.ownerSet.has(signer)) {
      // 非当前所有者：既可能是伪造，也可能是签名载荷与审批内容不匹配
      throw new InvalidApprovalSignatureError(
        'signature does not match approval payload or signer is not a current owner',
      );
    }
    if (record.signers.includes(signer)) {
      throw new DuplicateApprovalSignatureError(`owner ${signer} already signed approval`);
    }
    record.signers.push(signer);
    return this.toApprovalView(record);
  }

  /**
   * 查询审批当前状态与有序签名者。未知 id → ApprovalNotFoundError。
   * 状态按查询时刻计算：过期优先（expired），其次版本漂移（conflicted），
   * 已提交（submitted），否则按签名数相对当前确认数给出 collecting / ready。
   */
  getTransactionApproval(approvalId: string): TransactionApproval {
    const record = this.approvals.get(approvalId);
    if (record === undefined) throw new ApprovalNotFoundError(`approval not found: ${approvalId}`);
    return this.toApprovalView(record);
  }

  /**
   * 在阈值满足后提交审批：按既有 safe-wallet/tx/v1 摘要入队一个普通交易任务，
   * 队列与终态行为与 submitTransaction 完全一致；只消费创建时预留的 nonce。
   *
   * 错误约定：
   *   - 未知 id → ApprovalNotFoundError
   *   - 已提交 → ApprovalAlreadySubmittedError
   *   - 已过截止时间 → ApprovalExpiredError（过期优先于版本冲突）
   *   - 版本漂移（未过期）→ ApprovalPolicyConflictError
   *   - 去重签名者不足当前确认数 → ApprovalThresholdNotMetError
   *   - 创建时 nonce 已被其他入口使用 → NonceAlreadyUsedError
   *   - 创建时 nonce 已不等于 expectedNonce（被其他 nonce 插队）→ ApprovalNonceConflictError
   *
   * 任一失败都不入队、不消费 nonce、不改策略。
   */
  submitApprovedTransaction(approvalId: string): WalletTask {
    const record = this.requireActiveApproval(approvalId);

    if (BigInt(record.signers.length) < this.confirmations) {
      throw new ApprovalThresholdNotMetError(
        `threshold not met: need ${this.confirmations} distinct current owners, got ${record.signers.length}`,
      );
    }
    // 重放防护优先于顺序判定（与既有提交一致）：nonce 已消费恒报 NonceAlreadyUsedError
    if (this.usedNonces.has(record.nonce)) throw new NonceAlreadyUsedError(record.nonce);
    if (record.nonce !== this.nextNonce) {
      throw new ApprovalNonceConflictError(record.nonce, this.nextNonce);
    }

    const payload: WalletTaskPayload = {
      kind: 'transaction',
      deadline: record.deadline,
      to: record.to,
      value: record.value,
      data: Buffer.from(record.data),
    };

    let task: WalletTask;
    try {
      task = this.queue.enqueue({
        nonce: record.nonce,
        digest: record.txDigest,
        payload,
        submittedAt: this.now(),
      });
    } catch (err) {
      // 与既有 submit 相同的队列防重归一：同一摘要任务已存在时表现为 nonce 复用
      if (err instanceof InvalidQueueStateError) throw new NonceAlreadyUsedError(record.nonce);
      throw err;
    }
    this.usedNonces.add(record.nonce);
    this.nextNonce = record.nonce + 1n;
    record.submitted = true;
    record.taskId = task.id;
    return task;
  }

  // ---------- 策略变更提交 ----------

  proposePolicyChange(sub: PolicyChangeSubmission, signatures: readonly Uint8Array[]): WalletTask {    return this.submit(
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
    const Invalid =
      kind === 'policy-change'
        ? InvalidPolicyChange
        : kind === 'transaction-batch'
          ? InvalidTransactionBatch
          : InvalidTransaction;

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
    } else if (kind === 'transaction-batch') {
      // 有序调用列表：1..64 项；逐项规范化收款地址、金额与 data（顺序保持不变）
      const calls = this.normalizeBatchCalls(raw.calls);
      const req: TransactionBatchRequest = {
        walletId: this.id,
        nonce,
        deadline,
        calls,
      };
      digest = hashTransactionBatch(req);
      payload = { kind: 'transaction-batch', deadline, calls };
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
   * 规范化批量调用列表：必须是 1..MAX_BATCH_CALLS 项的数组，每项是对象，
   * 收款地址合法且非零、金额为 256 位以内非负整数、data 必须是 Uint8Array。
   * 保持输入顺序；任何畸形都归为 InvalidTransactionBatch。
   */
  private normalizeBatchCalls(rawCalls: unknown): BatchCall[] {
    if (!Array.isArray(rawCalls) || rawCalls.length === 0) {
      throw new InvalidTransactionBatch('calls must be a non-empty array');
    }
    if (rawCalls.length > MAX_BATCH_CALLS) {
      throw new InvalidTransactionBatch(`too many calls: ${rawCalls.length} > ${MAX_BATCH_CALLS}`);
    }
    const calls: BatchCall[] = [];
    for (const rawCall of rawCalls) {
      if (typeof rawCall !== 'object' || rawCall === null) {
        throw new InvalidTransactionBatch('each batch call must be an object');
      }
      const call = rawCall as Record<string, unknown>;
      const to = normalizeAddress(call.to as string);
      if (to === null || isZeroAddress(to)) {
        throw new InvalidTransactionBatch('invalid or zero recipient address in batch call');
      }
      const value = toBigInt(call.value, InvalidTransactionBatch, 'value');
      if (!isNonNegativeInteger(value)) {
        throw new InvalidTransactionBatch('batch call value out of range');
      }
      if (!(call.data instanceof Uint8Array)) {
        throw new InvalidTransactionBatch('batch call data must be a Uint8Array');
      }
      // 复制一份，避免入队后调用方再改动同一缓冲区影响任务内容/摘要
      calls.push({ to, value, data: Buffer.from(call.data) });
    }
    return calls;
  }

  /**
   * 取出“仍可加签 / 提交”的审批，并套用生命周期前置判定。
   * 顺序：存在 → 已提交 → 过期（优先）→ 版本漂移。
   */
  private requireActiveApproval(approvalId: string): ApprovalRecord {
    const record = this.approvals.get(approvalId);
    if (record === undefined) throw new ApprovalNotFoundError(`approval not found: ${approvalId}`);
    if (record.submitted) {
      throw new ApprovalAlreadySubmittedError(`approval ${approvalId} already submitted`);
    }
    if (record.deadline < this.now()) {
      throw new ApprovalExpiredError(`approval deadline ${record.deadline} already passed`);
    }
    if (record.version !== this.version) {
      throw new ApprovalPolicyConflictError(
        `policy version drifted: approval bound ${record.version}, current ${this.version}`,
      );
    }
    return record;
  }

  /**
   * 生成审批的只读视图：状态按查询时刻的时钟、策略版本与签名数计算。
   * 过期优先于版本漂移；已提交的审批保持 submitted（即使后来过期或版本变化）。
   */
  private toApprovalView(record: ApprovalRecord): TransactionApproval {
    let status: TransactionApprovalStatus;
    if (record.submitted) {
      status = 'submitted';
    } else if (record.deadline < this.now()) {
      status = 'expired';
    } else if (record.version !== this.version) {
      status = 'conflicted';
    } else {
      status = BigInt(record.signers.length) >= this.confirmations ? 'ready' : 'collecting';
    }
    return {
      id: record.id,
      digest: record.approvalDigest.toString('hex'),
      version: record.version,
      nonce: record.nonce,
      deadline: record.deadline,
      confirmations: record.confirmations,
      to: record.to,
      value: record.value,
      data: Buffer.from(record.data),
      signers: [...record.signers],
      status,
    };
  }

  /** 按“当前策略”的所有者集合与确认数校验签名收集 */
  private verifyThresholdSignatures(
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
      // 原子批量：执行器一次性产出整批回执。调用方（队列）在本回调正常返回后才写入
      // executed 终态；本回调抛出则整批进入 failed，不产生部分执行回执。
      // 截止时间同样不是执行闸门，与单笔普通交易保持一致。
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
