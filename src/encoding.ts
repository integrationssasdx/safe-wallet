/**
 * 规范化编码与签名摘要。
 *
 * 两类操作使用不同的域分隔标签，签名互不兼容（普通交易签名不能用于策略变更，反之亦然）：
 *   - 普通交易：   "safe-wallet/tx/v1"
 *   - 策略变更：   "safe-wallet/policy-change/v1"
 *
 * 编码规则（全部大端）：
 *   encBytes(b)  = uint32(len) || b
 *   encStr(s)    = uint32(len) || utf8(s)
 *   encUint(n)   = n 的定长 32 字节大端表示
 *   encList(xs)  = uint32(count) || concat(encBytes(x))
 *
 * 普通交易载荷不包含策略版本字段（保持既有交易格式不变）；
 * 策略变更载荷显式绑定钱包标识、操作标签、当前版本、新所有者、新确认数、nonce、截止时间。
 */

import { sha256, hexToBytes, type Address } from './crypto.ts';

const TAG_TX = 'safe-wallet/tx/v1';
const TAG_POLICY_CHANGE = 'safe-wallet/policy-change/v1';

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
