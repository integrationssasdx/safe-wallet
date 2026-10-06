import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encBytes,
  encList,
  encStr,
  encUint,
  hashApprovalRevocation,
  hashCancellation,
  hashPolicyChange,
  hashTransaction,
} from '../src/encoding.ts';
import { actors, addresses } from './helpers.ts';

test('定长编码：uint32 长度前缀 + 内容', () => {
  assert.deepEqual(encBytes(Buffer.from('abc')), Buffer.from([0, 0, 0, 3, 0x61, 0x62, 0x63]));
});

test('encStr 与 encBytes(utf8) 一致', () => {
  assert.deepEqual(encStr('abc'), encBytes(Buffer.from('abc')));
  // 多字节字符按 UTF-8 字节计数，避免长度歧义
  const s = '多签';
  assert.deepEqual(encStr(s), encBytes(Buffer.from(s, 'utf8')));
});

test('encUint：大端 32 字节；0 与大数', () => {
  const zero = encUint(0n);
  assert.equal(zero.length, 32);
  assert.ok(zero.equals(Buffer.alloc(32)));
  const one = encUint(1n);
  assert.equal(one[31], 1);
  const max = (1n << 256n) - 1n;
  assert.deepEqual(encUint(max), Buffer.alloc(32, 0xff));
  assert.throws(() => encUint(-1n));
  assert.throws(() => encUint(1n << 256n));
});

test('encList：数量前缀 + 每个元素独立长度前缀', () => {
  const got = encList([Buffer.from('a'), Buffer.from('bb')]);
  assert.deepEqual(
    got,
    Buffer.concat([
      Buffer.from([0, 0, 0, 2]),
      Buffer.from([0, 0, 0, 1, 0x61]),
      Buffer.from([0, 0, 0, 2, 0x62, 0x62]),
    ]),
  );
});

test('长度前缀编码无歧义：拼接攻击无法构造碰撞', () => {
  // ["ab","c"] vs ["a","bc"]：朴素 concat 相同，长度前缀编码必须不同
  const a = encList([Buffer.from('ab'), Buffer.from('c')]);
  const b = encList([Buffer.from('a'), Buffer.from('bc')]);
  assert.ok(!a.equals(b));
});

const baseTx = () => ({
  walletId: 'wallet-A',
  nonce: 7n,
  deadline: 9999n,
  to: '0x' + '11'.repeat(20),
  value: 123n,
  data: Buffer.from('hello'),
});

test('普通交易摘要：确定性 32 字节', () => {
  const h1 = hashTransaction(baseTx());
  const h2 = hashTransaction(baseTx());
  assert.equal(h1.length, 32);
  assert.ok(h1.equals(h2));
});

test('普通交易摘要对任一字段敏感', () => {
  const base = baseTx();
  const variants = [
    { ...base, walletId: 'wallet-B' },
    { ...base, nonce: 8n },
    { ...base, deadline: 9998n },
    { ...base, to: '0x' + '22'.repeat(20) },
    { ...base, value: 124n },
    { ...base, data: Buffer.from('hellp') },
    { ...base, data: Buffer.from('hell') },
  ];
  const h0 = hashTransaction(base);
  for (const v of variants) assert.ok(!hashTransaction(v).equals(h0));
});

test('普通交易摘要不含策略版本：无版本入参且编码稳定', () => {
  // 同一交易内容在不同“外部版本语境”下摘要必须相同（版本不参与编码）
  assert.ok(hashTransaction(baseTx()).equals(hashTransaction({ ...baseTx() })));
});

const basePc = () => {
  const [a, b, c] = actors(3);
  return {
    walletId: 'wallet-A',
    version: 3n,
    nonce: 7n,
    deadline: 9999n,
    newOwners: addresses([a, b, c]),
    newConfirmations: 2n,
  };
};

test('策略变更摘要：确定性 32 字节', () => {
  const p = basePc();
  assert.ok(hashPolicyChange(p).equals(hashPolicyChange({ ...p })));
});

test('策略变更摘要对版本/新所有者/新确认数/nonce/截止时间/钱包标识均敏感', () => {
  const p = basePc();
  const [, , , newbie] = actors(4);
  const variants = [
    { ...p, version: 4n },
    { ...p, nonce: 8n },
    { ...p, deadline: 9998n },
    { ...p, newConfirmations: 3n },
    { ...p, walletId: 'wallet-B' },
    { ...p, newOwners: [p.newOwners[0]!, p.newOwners[1]!, newbie.address] },
    // 仅调换所有者顺序也必须不同
    { ...p, newOwners: [p.newOwners[1]!, p.newOwners[0]!, p.newOwners[2]!] },
  ];
  const h0 = hashPolicyChange(p);
  for (const v of variants) assert.ok(!hashPolicyChange(v).equals(h0));
});

test('两类操作域分隔：即使字段相同，交易摘要与策略变更摘要也不相等', () => {
  const [a, b] = actors(2);
  const tx = hashTransaction({
    walletId: 'w',
    nonce: 1n,
    deadline: 2n,
    to: a.address,
    value: 0n,
    data: new Uint8Array(),
  });
  const pc = hashPolicyChange({
    walletId: 'w',
    version: 1n,
    nonce: 1n,
    deadline: 2n,
    newOwners: addresses([a, b]),
    newConfirmations: 1n,
  });
  assert.ok(!tx.equals(pc));
});

const baseRevoke = () => ({
  walletId: 'wallet-A',
  approvalDigest: '0x' + 'ab'.repeat(32),
  nonce: 7n,
  deadline: 9999n,
});

test('审批撤销摘要：确定性 32 字节，对任一绑定字段敏感', () => {
  const h1 = hashApprovalRevocation(baseRevoke());
  const h2 = hashApprovalRevocation(baseRevoke());
  assert.equal(h1.length, 32);
  assert.ok(h1.equals(h2));
  for (const v of [
    { ...baseRevoke(), walletId: 'wallet-B' },
    { ...baseRevoke(), approvalDigest: '0x' + 'cd'.repeat(32) },
    { ...baseRevoke(), nonce: 8n },
    { ...baseRevoke(), deadline: 9998n },
  ]) {
    assert.ok(!hashApprovalRevocation(v).equals(h1));
  }
});

test('审批撤销域独立：与取消摘要即使编码字段数值相同也不相等', () => {
  const r = hashApprovalRevocation(baseRevoke());
  const c = hashCancellation({
    walletId: 'wallet-A',
    taskDigest: '0x' + 'ab'.repeat(32),
    nonce: 7n,
    deadline: 9999n,
  });
  assert.ok(!r.equals(c));
});
