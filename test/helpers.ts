import { generateKeyPair, signDigest, sha256, type Address, type KeyPair } from '../src/crypto.ts';
import { hashCancellation, hashPolicyChange, hashTransaction } from '../src/encoding.ts';

export interface Actor extends KeyPair {}

export function actors(n: number): Actor[] {
  return Array.from({ length: n }, () => generateKeyPair());
}

export function addresses(list: Actor[]): Address[] {
  return list.map((a) => a.address);
}

/** 可控时钟 */
export function fakeClock(start = 1000n): { now: () => bigint; advance: (s: bigint) => void; set: (t: bigint) => void } {
  let t = start;
  return {
    now: () => t,
    advance: (s: bigint) => {
      t += s;
    },
    set: (v: bigint) => {
      t = v;
    },
  };
}

export interface TxParams {
  walletId: string;
  nonce: bigint;
  deadline: bigint;
  to: Address;
  value?: bigint;
  data?: Uint8Array;
}

export function signTransaction(
  signers: Actor[],
  p: TxParams,
  opts: { mutate?: (base: TxParams) => TxParams } = {},
): Buffer[] {
  const base: TxParams = {
    walletId: p.walletId,
    nonce: p.nonce,
    deadline: p.deadline,
    to: p.to,
    value: p.value ?? 0n,
    data: p.data ?? new Uint8Array(),
  };
  const finalParams = opts.mutate ? opts.mutate(base) : base;
  const digest = hashTransaction({
    ...finalParams,
    value: finalParams.value ?? 0n,
    data: finalParams.data ?? new Uint8Array(),
  });
  return signers.map((s) => signDigest(s.privateKey, digest));
}

export interface PcParams {
  walletId: string;
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  newOwners: Address[];
  newConfirmations: bigint;
}

export function signPolicyChange(
  signers: Actor[],
  p: PcParams,
  opts: { mutate?: (base: PcParams) => PcParams } = {},
): Buffer[] {
  const finalParams = opts.mutate ? opts.mutate(p) : p;
  const digest = hashPolicyChange(finalParams);
  return signers.map((s) => signDigest(s.privateKey, digest));
}

export interface CancelParams {
  walletId: string;
  taskDigest: string;
  nonce: bigint;
  deadline: bigint;
}

export function signCancellation(
  signers: Actor[],
  p: CancelParams,
  opts: { mutate?: (base: CancelParams) => CancelParams } = {},
): Buffer[] {
  const finalParams = opts.mutate ? opts.mutate(p) : p;
  const digest = hashCancellation(finalParams);
  return signers.map((s) => signDigest(s.privateKey, digest));
}

export { sha256 };
