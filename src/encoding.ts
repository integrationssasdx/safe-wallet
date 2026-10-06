/**
 * 规范化编码与签名摘要。
 *
 * 各类操作使用不同的域分隔标签，签名互不兼容（任一类型的签名都不能用于其他类型）：
 *   - 普通交易：         "safe-wallet/tx/v1"
 *   - 原子批量交易：     "safe-wallet/tx-batch/v1"
 *   - 策略变更：         "safe-wallet/policy-change/v1"
 *   - 任务取消：         "safe-wallet/cancel/v1"
 *   - 普通交易分阶段审批："safe-wallet/tx-approval/v1"
 *   - 策略变更分阶段审批："safe-wallet/policy-change-approval/v1"
 *
 * 编码规则（全部大端）：
 *   encBytes(b)  = uint32(len) || b
 *   encStr(s)    = uint32(len) || utf8(s)
 *   encUint(n)   = n 的定长 32 字节大端表示
 *   encList(xs)  = uint32(count) || concat(encBytes(x))
 *
 * 普通交易载荷不包含策略版本字段（保持既有交易格式不变）；
 * 批量交易载荷绑定钱包标识、nonce、截止时间，以及按顺序编码的全部调用
 * （每调用固定按“收款地址 || 金额 || data”编码，再以 encList 绑定项数与顺序）；
 * 策略变更载荷显式绑定钱包标识、操作标签、当前版本、新所有者、新确认数、nonce、截止时间。
 */

import { sha256, hexToBytes, type Address } from './crypto.ts';

const TAG_TX = 'safe-wallet/tx/v1';
const TAG_TX_BATCH = 'safe-wallet/tx-batch/v1';
const TAG_POLICY_CHANGE = 'safe-wallet/policy-change/v1';
const TAG_CANCEL = 'safe-wallet/cancel/v1';
const TAG_TX_APPROVAL = 'safe-wallet/tx-approval/v1';
const TAG_POLICY_APPROVAL = 'safe-wallet/policy-change-approval/v1';

// ---------- 编码原语 ----------

export function encBytes(data: Uint8Array): Buffer {
  const b = Buffer.from(data);
  const out = Buffer.alloc(4 + b.length);
  out.writeUInt32BE(b.length, 0);
  b.copy(out, 4);
  return out;
}

export function encStr(s: string): Buffer {
  return encBytes(Buffer.from(s, 'utf8'));
}

export function encUint(n: bigint | number): Buffer {
  const v = BigInt(n);
  if (v < 0n) throw new Error('cannot encode negative integer');
  if (v >> 256n !== 0n) throw new Error('integer exceeds 32 bytes');
  const out = Buffer.alloc(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function encList(items: Uint8Array[]): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(items.length, 0);
  return Buffer.concat([head, ...items.map(encBytes)]);
}

function digest(tag: string, parts: Buffer[]): Buffer {
  return sha256(Buffer.concat([encStr(tag), ...parts]));
}

// ---------- 请求类型 ----------

export interface TransactionRequest {
  /** 钱包标识（部署时确定；参与签名绑定，防止跨钱包重放） */
  walletId: string;
  nonce: bigint;
  /** Unix 秒级截止时间（也接受毫秒级大数；语义由调用方约定，引擎按数值比较） */
  deadline: bigint;
  to: Address;
  value: bigint;
  data: Uint8Array;
}

export interface PolicyChangeRequest {
  walletId: string;
  /** 提交时绑定的当前策略版本 */
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  newOwners: Address[];
  newConfirmations: bigint;
}

/** 批量交易中的单次调用：收款地址、金额、附带数据 */
export interface BatchTransactionCall {
  to: Address;
  value: bigint;
  data: Uint8Array;
}

export interface TransactionBatchRequest {
  /** 钱包标识（部署时确定；参与签名绑定，防止跨钱包重放） */
  walletId: string;
  nonce: bigint;
  deadline: bigint;
  /** 有序调用列表（1..64 项）；顺序参与签名，不得改变 */
  calls: BatchTransactionCall[];
}

export interface CancellationRequest {
  walletId: string;
  /** 目标任务的签名摘要（hex）：把取消请求绑定到唯一任务，防止改绑其他任务 */
  taskDigest: string;
  nonce: bigint;
  deadline: bigint;
}

export interface TransactionApprovalRequest {
  walletId: string;
  /** 创建审批时绑定的当前策略版本 */
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  to: Address;
  value: bigint;
  data: Uint8Array;
}

export interface PolicyApprovalRequest {
  walletId: string;
  /** 创建审批时绑定的当前策略版本 */
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  /** 新所有者顺序（有序列表，顺序参与签名绑定） */
  newOwners: Address[];
  newConfirmations: bigint;
}

function walletIdBytes(walletId: string): Buffer {
  // 钱包标识统一按 UTF-8 参与签名绑定（任意字符串均可）
  return Buffer.from(walletId, 'utf8');
}

function deadlineToBigint(d: bigint | number): bigint {
  return BigInt(d);
}

/** 普通交易的签名摘要（不含策略版本字段） */
export function hashTransaction(req: {
  walletId: string;
  nonce: bigint | number;
  deadline: bigint | number;
  to: Address;
  value: bigint | number;
  data: Uint8Array;
}): Buffer {
  return digest(TAG_TX, [
    encBytes(walletIdBytes(req.walletId)),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
    encBytes(hexToBytes(req.to)),
    encUint(req.value),
    encBytes(req.data),
  ]);
}

/**
 * 原子批量普通交易的签名摘要：绑定钱包标识、nonce、截止时间，以及按顺序编码的全部调用。
 * 每个调用固定按“收款地址 || 金额 || data”编码为一段，再以 encList 绑定项数与顺序：
 * 任一调用的收款方/金额/data 变化，或调用顺序/项数变化，都会改变摘要。
 */
export function hashTransactionBatch(req: {
  walletId: string;
  nonce: bigint | number;
  deadline: bigint | number;
  calls: readonly {
    to: Address;
    value: bigint | number;
    data: Uint8Array;
  }[];
}): Buffer {
  const encodedCalls = req.calls.map((call) =>
    Buffer.concat([
      encBytes(hexToBytes(call.to)),
      encUint(call.value),
      encBytes(call.data),
    ]),
  );
  return digest(TAG_TX_BATCH, [
    encBytes(walletIdBytes(req.walletId)),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
    encList(encodedCalls),
  ]);
}

/** 策略变更的签名摘要：显式绑定版本、新所有者与新确认数 */
export function hashPolicyChange(req: {
  walletId: string;
  version: bigint | number;
  nonce: bigint | number;
  deadline: bigint | number;
  newOwners: Address[];
  newConfirmations: bigint | number;
}): Buffer {
  return digest(TAG_POLICY_CHANGE, [
    encBytes(walletIdBytes(req.walletId)),
    encUint(req.version),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
    encUint(req.newConfirmations),
    encList(req.newOwners.map((o) => hexToBytes(o))),
  ]);
}

/** 任务取消的签名摘要：绑定钱包标识、目标任务摘要、nonce 与截止时间 */
export function hashCancellation(req: {
  walletId: string;
  taskDigest: string;
  nonce: bigint | number;
  deadline: bigint | number;
}): Buffer {
  return digest(TAG_CANCEL, [
    encBytes(walletIdBytes(req.walletId)),
    encBytes(hexToBytes(req.taskDigest)),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
  ]);
}

/**
 * 普通交易分阶段审批的签名摘要：绑定钱包标识、创建时的策略版本与完整交易字段
 * （nonce、截止时间、收款地址、金额、data 副本）。与 safe-wallet/tx/v1 域不同，
 * 审批签名与直接提交签名互不通用；版本漂移后旧审批签名自然失效（由引擎按版本拦截）。
 */
export function hashTransactionApproval(req: {
  walletId: string;
  version: bigint | number;
  nonce: bigint | number;
  deadline: bigint | number;
  to: Address;
  value: bigint | number;
  data: Uint8Array;
}): Buffer {
  return digest(TAG_TX_APPROVAL, [
    encBytes(walletIdBytes(req.walletId)),
    encUint(req.version),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
    encBytes(hexToBytes(req.to)),
    encUint(req.value),
    encBytes(req.data),
  ]);
}

/**
 * 策略变更分阶段审批的签名摘要：绑定钱包标识、创建时策略版本、nonce、截止时间与目标新策略
 * （新确认数、按顺序编码的新所有者列表）。使用独立的 safe-wallet/policy-change-approval/v1
 * 域：与既有 safe-wallet/policy-change/v1 直接提交签名互不通用；版本漂移后旧审批签名自然失效
 * （由引擎按版本拦截）。新所有者列表顺序参与签名，顺序变化即改变摘要。
 */
export function hashPolicyApproval(req: {
  walletId: string;
  version: bigint | number;
  nonce: bigint | number;
  deadline: bigint | number;
  newOwners: Address[];
  newConfirmations: bigint | number;
}): Buffer {
  return digest(TAG_POLICY_APPROVAL, [
    encBytes(walletIdBytes(req.walletId)),
    encUint(req.version),
    encUint(req.nonce),
    encUint(deadlineToBigint(req.deadline)),
    encUint(req.newConfirmations),
    encList(req.newOwners.map((o) => hexToBytes(o))),
  ]);
}
