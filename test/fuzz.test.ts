import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import {
  InvalidPolicyChange,
  InvalidTransaction,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { actors, addresses, fakeClock } from './helpers.ts';

const EXPECTED = new Set([
  InvalidTransaction.name,
  InvalidPolicyChange.name,
  NonceAlreadyUsedError.name,
  RequestExpired.name,
]);

function setup() {
  const ownerActors = actors(3);
  const clock = fakeClock(1000n);
  const wallet = new MultiSigWallet({
    id: 'w',
    owners: addresses(ownerActors),
    confirmations: 2n,
    now: clock.now,
  });
  return { wallet };
}

// 提交路径对任何畸形输入，只能抛出四类“已约定”错误之一（不应泄漏原生 TypeError 等）
test('对抗输入：策略变更提交仅抛出约定错误类型', () => {
  const { wallet } = setup();
  const goodOwners = addresses(actors(2));
  const garbage: unknown[] = [
    undefined,
    null,
    'abc',
    -1.5,
    Number.NaN,
    {},
    [],
    2n ** 300n,
    { toString: () => { throw new Error('boom'); } },
  ];
  const sigs = [new Uint8Array(65), new Uint8Array(65)];
  let checks = 0;
  for (const g of garbage) {
    for (const field of ['version', 'nonce', 'deadline', 'newConfirmations'] as const) {
      const sub: Record<string, unknown> = {
        version: 1n,
        nonce: 0n,
        deadline: 5000n,
        newOwners: goodOwners,
        newConfirmations: 1n,
      };
      sub[field] = g;
      assert.throws(
        () => wallet.proposePolicyChange(sub as any, sigs),
        (err: unknown) => {
          const e = err as Error;
          assert.ok(EXPECTED.has(e.name), `unexpected error ${e.name} for field ${field}`);
          return true;
        },
      );
      checks++;
    }
  }
  // 非法 newOwners 形状
  for (const owners of [undefined, null, 'x', 42, {}, [null], [123], ['0xZZ']]) {
    assert.throws(
      () =>
        wallet.proposePolicyChange(
          { version: 1n, nonce: 0n, deadline: 5000n, newOwners: owners as any, newConfirmations: 1n },
          sigs,
        ),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
    checks++;
  }
  assert.ok(checks > 40);
});

test('对抗输入：普通交易提交仅抛出约定错误类型', () => {
  const { wallet } = setup();
  const to = actors(1)[0]!.address;
  const sigs = [new Uint8Array(65), new Uint8Array(65)];
  const garbage: unknown[] = [undefined, null, 'abc', -1.5, {}, 2n ** 300n];
  for (const g of garbage) {
    for (const field of ['nonce', 'deadline', 'value', 'to'] as const) {
      const sub: Record<string, unknown> = {
        nonce: 0n,
        deadline: 5000n,
        to,
        value: 1n,
      };
      sub[field] = g;
      assert.throws(
        () => wallet.submitTransaction(sub as any, sigs),
        (err: unknown) => EXPECTED.has((err as Error).name),
      );
    }
  }
});

test('签名集合的畸形元素不泄漏非约定错误', () => {
  const { wallet } = setup();
  const to = actors(1)[0]!.address;
  const badSigs: unknown[] = [
    [],
    [null],
    [undefined],
    ['deadbeef'],
    [new Uint8Array(0)],
    [new Uint8Array(64), new Uint8Array(65)],
    [new Uint8Array(65).fill(0xff)],
    'not-an-array',
  ];
  for (const sigs of badSigs) {
    assert.throws(
      () => wallet.submitTransaction({ nonce: 0n, deadline: 5000n, to, value: 1n }, sigs as any),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
  }
});
