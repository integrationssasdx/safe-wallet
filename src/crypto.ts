/**
 * 零依赖密码学原语：
 * - SHA-256（基于 node:crypto 的摘要/HMAC）
 * - secp256k1 点运算、RFC 6979 确定性 ECDSA 签名、公钥恢复
 * - 地址 = SHA-256(未压缩公钥 65 字节) 的末 20 字节（0x 前缀 EIP-55 之外的小写十六进制）
 *
 * 签名统一为 65 字节：r(32) || s(32) || v(1)，其中 v 为公钥恢复标识（0..3）。
 * 所有产出签名强制 low-s（s <= N/2），天然具备抗可塑性。
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';

// ---------- 基础类型 ----------

/** 0x 开头的 40 位小写十六进制地址 */
export type Address = string;

export const ZERO_ADDRESS: Address = '0x' + '00'.repeat(20);

export function sha256(data: Uint8Array): Buffer {
  return createHash('sha256').update(data).digest();
}

export function hexToBytes(hex: string): Buffer {
  if (typeof hex !== 'string') throw new TypeError('hex value must be a string');
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2 !== 0) {
    throw new Error(`invalid hex string: ${hex}`);
  }
  return Buffer.from(h, 'hex');
}

export function bytesToHex(bytes: Uint8Array): string {
  return '0x' + Buffer.from(bytes).toString('hex');
}

/** 规范化为 0x + 小写；非法返回 null */
export function normalizeAddress(value: string): Address | null {
  if (typeof value !== 'string') return null;
  const h = value.startsWith('0x') ? value.slice(2) : null;
  if (h === null || h.length !== 40 || !/^[0-9a-fA-F]{40}$/.test(h)) return null;
  return ('0x' + h.toLowerCase()) as Address;
}

export function isZeroAddress(addr: Address): boolean {
  return addr === ZERO_ADDRESS;
}

// ---------- secp256k1 曲线参数 ----------

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const HALF_N = N >> 1n;
const Gx = BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240');
const Gy = BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424');

type Jacobian = { x: bigint; y: bigint; z: bigint } | null;
type Affine = { x: bigint; y: bigint } | null;

const mod = (a: bigint): bigint => ((a % P) + P) % P;
const modN = (a: bigint): bigint => ((a % N) + N) % N;

function invMod(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('no modular inverse');
  return ((oldS % m) + m) % m;
}

function toAffine(p: Jacobian): Affine {
  if (p === null) return null;
  if (p.z === 0n) return null;
  const zi = invMod(p.z, P);
  const zi2 = mod(zi * zi);
  const zi3 = mod(zi2 * zi);
  return { x: mod(p.x * zi2), y: mod(p.y * zi3) };
}

/** Jacobian 点倍加（a=0 曲线） */
function jacDouble(p: Jacobian): Jacobian {
  if (p === null || p.y === 0n) return null;
  const y2 = mod(p.y * p.y);
  const y4 = mod(y2 * y2);
  const s = mod(4n * p.x * y2);
  const m = mod(3n * p.x * p.x);
  const x3 = mod(m * m - 2n * s);
  const y3 = mod(m * (s - x3) - 8n * y4);
  const z3 = mod(2n * p.y * p.z);
  return { x: x3, y: y3, z: z3 };
}

/** Jacobian P + 仿射 Q（mixed addition） */
function jacAddAffine(p: Jacobian, q: { x: bigint; y: bigint }): Jacobian {
  if (p === null) return { x: q.x, y: q.y, z: 1n };
  const z1z1 = mod(p.z * p.z);
  const u2 = mod(q.x * z1z1);
  const s2 = mod(q.y * z1z1 * p.z);
  if (u2 === p.x) {
    if (s2 !== p.y) return null;
    return jacDouble(p);
  }
  const h = mod(u2 - p.x);
  const hh = mod(h * h);
  const i = mod(4n * hh);
  const j = mod(h * i);
  const r = mod(2n * (s2 - p.y));
  const v = mod(p.x * i);
  const x3 = mod(r * r - j - 2n * v);
  const y3 = mod(r * (v - x3) - 2n * p.y * j);
  const z3 = mod((p.z + h) * (p.z + h) - z1z1 - hh);
  return { x: x3, y: y3, z: z3 };
}

/** 标量乘仿射点（double-and-add） */
function scalarMul(k: bigint, point: { x: bigint; y: bigint }): Jacobian {
  let n = ((k % N) + N) % N;
  let result: Jacobian = null;
  let addend: Jacobian = { x: point.x, y: point.y, z: 1n };
  while (n > 0n) {
    if (n & 1n) result = jacAddAffine(result, toAffine(addend)!);
    addend = jacDouble(addend);
    n >>= 1n;
  }
  return result;
}

const G = { x: Gx, y: Gy };

// ---------- 整数 / 定长字节 ----------

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes(n: bigint, length: number): Buffer {
  const out = Buffer.alloc(length);
  let v = n;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function to32(n: bigint): Buffer {
  return bigIntToBytes(n, 32);
}

// ---------- 密钥与地址 ----------

export interface KeyPair {
  /** 32 字节私钥标量（大端） */
  privateKey: Buffer;
  /** 65 字节未压缩公钥 0x04 || X || Y */
  publicKey: Buffer;
  address: Address;
}

export function publicKeyFromScalar(d: bigint): Buffer {
  if (d <= 0n || d >= N) throw new Error('private scalar out of range');
  const q = toAffine(scalarMul(d, G))!;
  return Buffer.concat([Buffer.from([0x04]), to32(q.x), to32(q.y)]);
}

export function addressFromPublicKey(publicKey: Uint8Array): Address {
  const pk = Buffer.from(publicKey);
  if (pk.length !== 65 || pk[0] !== 0x04) throw new Error('expected 65-byte uncompressed public key');
  return bytesToHex(sha256(pk).subarray(12)) as Address;
}

export function generateKeyPair(): KeyPair {
  let d: bigint;
  do {
    d = bytesToBigInt(randomBytes(32)) % N;
  } while (d === 0n);
  const publicKey = publicKeyFromScalar(d);
  return { privateKey: to32(d), publicKey, address: addressFromPublicKey(publicKey) };
}

/** 由 32 字节私钥重建密钥对（测试/钱包导入用） */
export function keyPairFromPrivate(privateKey: Uint8Array): KeyPair {
  const sk = Buffer.from(privateKey);
  if (sk.length !== 32) throw new Error('private key must be 32 bytes');
  const d = bytesToBigInt(sk);
  const publicKey = publicKeyFromScalar(d);
  return { privateKey: sk, publicKey, address: addressFromPublicKey(publicKey) };
}

// ---------- RFC 6979 确定性 nonce ----------

function rfc6979K(d: bigint, e: bigint): () => bigint {
  const x = to32(d);
  const h1 = to32(e);
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);
  const hmac = () => createHmac('sha256', k).update(v).digest();
  k = createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x00]), x, h1])).digest();
  v = hmac();
  k = createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x01]), x, h1])).digest();
  v = hmac();
  // 此时 v 即第一个候选 T；每次取出后按 RFC 推进 K、V
  return () => {
    const candidate = bytesToBigInt(v);
    k = createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x00])])).digest();
    v = hmac();
    return candidate;
  };
}

// ---------- 公钥恢复 ----------

function decompressPoint(x: bigint, oddY: boolean): { x: bigint; y: bigint } | null {
  if (x >= P) return null;
  const alpha = mod(x * x * x + 7n);
  // p ≡ 3 (mod 4)
  let y = modPow(alpha, (P + 1n) / 4n, P);
  if (mod(y * y) !== alpha) return null;
  if ((y & 1n) === (oddY ? 0n : 1n)) y = P - y;
  return { x, y };
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

export interface RecoveredSignature {
  r: bigint;
  s: bigint;
  recoveryId: number;
}

/** 解析 65 字节签名并做范围/规范性检查（low-s） */
export function parseSignature(sig: Uint8Array): RecoveredSignature | null {
  const b = Buffer.from(sig);
  if (b.length !== 65) return null;
  const r = bytesToBigInt(b.subarray(0, 32));
  const s = bytesToBigInt(b.subarray(32, 64));
  const recoveryId = b.readUInt8(64);
  if (r <= 0n || r >= N || s <= 0n || s >= N) return null;
  if (s > HALF_N) return null; // 拒绝 high-s（可塑性签名）
  if (recoveryId > 3) return null;
  return { r, s, recoveryId };
}

/**
 * 由摘要与 65 字节签名恢复签名者未压缩公钥（65 字节）。
 * 签名必须 low-s；恢复标识非法或点不在曲线上时返回 null。
 */
export function recoverPublicKey(digest: Uint8Array, signature: Uint8Array): Buffer | null {
  const parsed = parseSignature(signature);
  if (parsed === null) return null;
  const { r, s, recoveryId } = parsed;
  if (digest.length !== 32) return null;

  const e = bytesToBigInt(digest) % N;
  // recoveryId 高位 j=1 表示 R.x = r + N（曲线阶）；低位为 y 的奇偶
  const x = r + ((recoveryId >> 1) === 1 ? N : 0n);
  const R = decompressPoint(x, (recoveryId & 1) === 1);
  if (R === null) return null;

  const rInv = invMod(r, N);
  // Q = r^-1 (s R - e G)
  const sR = scalarMul(modN(s), R);
  const negEG = scalarMul(modN(-e), G);
  const negEGAffine = toAffine(negEG);
  const sum = negEGAffine === null ? sR : jacAddAffine(sR, negEGAffine);
  const Q = toAffine(scalarMulPoint(rInv, sum));
  if (Q === null) return null;
  return Buffer.concat([Buffer.from([0x04]), to32(Q.x), to32(Q.y)]);
}

/** 由摘要与 65 字节签名恢复签名者地址 */
export function recoverAddress(digest: Uint8Array, signature: Uint8Array): Address | null {
  const pub = recoverPublicKey(digest, signature);
  return pub === null ? null : addressFromPublicKey(pub);
}

/** Jacobian 点的标量乘（恢复时 rInv 作用于加和点） */
function scalarMulPoint(k: bigint, point: Jacobian): Jacobian {
  const affine = toAffine(point);
  if (affine === null) return null;
  return scalarMul(k, affine);
}

// ---------- 签名 ----------

export interface SignedDigest {
  /** 65 字节 r || s || v */
  signature: Buffer;
}

/** 用私钥对 32 字节摘要做确定性 ECDSA 签名（RFC 6979，强制 low-s） */
export function signDigest(privateKey: Uint8Array, digest: Uint8Array): Buffer {
  const sk = Buffer.from(privateKey);
  if (sk.length !== 32) throw new Error('private key must be 32 bytes');
  if (digest.length !== 32) throw new Error('digest must be 32 bytes');
  const d = bytesToBigInt(sk);
  if (d <= 0n || d >= N) throw new Error('invalid private key');
  const e = bytesToBigInt(digest) % N;
  const nextK = rfc6979K(d, e);

  for (let attempt = 0; attempt < 16; attempt++) {
    const k = nextK();
    if (k <= 0n || k >= N) continue;
    const R = toAffine(scalarMul(k, G))!;
    const r = R.x % N;
    if (r === 0n) continue;
    let s = modN(invMod(k, N) * modN(e + r * d));
    if (s === 0n) continue;
    let recoveryId = (R.x >= N ? 2 : 0) | Number(R.y & 1n);
    if (s > HALF_N) {
      s = N - s;
      recoveryId ^= 1;
    }
    const sig = Buffer.concat([to32(r), to32(s), Buffer.from([recoveryId])]);
    // 自检：恢复地址必须与私钥对应地址一致
    const selfAddress = addressFromPublicKey(publicKeyFromScalar(d));
    if (recoverAddress(digest, sig) === selfAddress) return sig;
  }
  throw new Error('failed to produce valid signature');
}
