import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, MAX_BATCH_CALLS } from '../src/wallet.ts';
import {
  InvalidCancellation,
  InvalidPolicyChange,
  InvalidTransaction,
  InvalidTransactionBatch,
  InvalidQueueStateError,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { hashTransaction, hashTransactionBatch } from '../src/encoding.ts';
import {
  actors,
  addresses,
  fakeClock,
  signCancellation,
  signPolicyChange,
  signTransaction,
  signTransactionBatch,
  type Actor,
  type BatchParams,
} from './helpers.ts';

const WALLET = 'wallet-batch';

function setup(ownerCount = 3, confirmations = 2n, start = 1000n) {
  const ownerActors = actors(ownerCount);
  const clock = fakeClock(start);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations,
    now: clock.now,
  });
  return { ownerActors, clock, wallet };
}

/** 生成 n 个互不相同的收款方 */
function recipients(n: number) {
  return actors(n).map((a) => a.address);
}

/** 默认两所有者签名的批量提交参数（nonce 0 / deadline 9000） */
function defaultCalls(): { to: string; value: bigint; data: Uint8Array }[] {
  const [a, b, c] = recipients(3);
  return [
    { to: a!, value: 10n, data: Buffer.from('first') },
    { to: b!, value: 20n, data: Buffer.from('second') },
    { to: c!, value: 0n, data: new Uint8Array() },
  ];
}

function batchParams(calls: { to: string; value: bigint; data?: Uint8Array }[], over: Partial<BatchParams> = {}): BatchParams {
  return {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    calls: calls.map((c) => ({ to: c.to, value: c.value, data: c.data ?? new Uint8Array() })),
    ...over,
  };
}

/** 用前两个所有者签名并提交批量交易 */
function submitBatch(
  wallet: MultiSigWallet,
  ownerActors: Actor[],
  calls: { to: string; value: bigint; data?: Uint8Array }[],
  over: Partial<BatchParams> = {},
  sigsOverride?: Uint8Array[],
) {
  const params = batchParams(calls, over);
  const sigs = sigsOverride ?? signTransactionBatch(ownerActors.slice(0, 2), params);
  return wallet.submitBatchTransaction(
    {
      nonce: params.nonce,
      deadline: params.deadline,
      calls: calls.map((c) => ({ to: c.to, value: c.value, data: c.data })),
    },
    sigs,
  );
}

// ---------- 摘要编码 ----------

// 固定收款方集合：保证摘要测试的“确定性”断言不受每次随机生成影响
const BATCH_TOS = recipients(3);

const baseBatch = () => ({
  walletId: 'wallet-A',
  nonce: 7n,
  deadline: 9999n,
  calls: [
    { to: BATCH_TOS[0]!, value: 1n, data: Buffer.from('x') },
    { to: BATCH_TOS[1]!, value: 2n, data: Buffer.from('yy') },
    { to: BATCH_TOS[2]!, value: 3n, data: new Uint8Array() },
  ],
});

test('批量摘要：确定性 32 字节', () => {
  const h1 = hashTransactionBatch(baseBatch());
  const h2 = hashTransactionBatch(baseBatch());
  assert.equal(h1.length, 32);
  assert.ok(h1.equals(h2));
});

test('批量摘要对钱包标识/nonce/deadline 与任一调用的 to/value/data 敏感', () => {
  const base = baseBatch();
  const otherTo = recipients(1)[0]!;
  const variants = [
    { ...base, walletId: 'wallet-B' },
    { ...base, nonce: 8n },
    { ...base, deadline: 9998n },
    { ...base, calls: [{ ...base.calls[0]!, to: otherTo }, base.calls[1]!, base.calls[2]!] },
    { ...base, calls: [{ ...base.calls[0]!, value: 99n }, base.calls[1]!, base.calls[2]!] },
    { ...base, calls: [{ ...base.calls[0]!, data: Buffer.from('z') }, base.calls[1]!, base.calls[2]!] },
  ];
  const h0 = hashTransactionBatch(base);
  for (const v of variants) assert.ok(!hashTransactionBatch(v).equals(h0));
});

test('批量摘要对调用顺序与调用数量敏感：顺序变化即不同摘要', () => {
  const base = baseBatch();
  const swapped = { ...base, calls: [base.calls[1]!, base.calls[0]!, base.calls[2]!] };
  assert.ok(!hashTransactionBatch(swapped).equals(hashTransactionBatch(base)));
  const fewer = { ...base, calls: [base.calls[0]!, base.calls[1]!] };
  assert.ok(!hashTransactionBatch(fewer).equals(hashTransactionBatch(base)));
});

test('批量摘要编码无拼接歧义：字段/调用边界由长度前缀固定', () => {
  const to = recipients(1)[0]!;
  const a = hashTransactionBatch({
    walletId: 'w',
    nonce: 0n,
    deadline: 1n,
    calls: [
      { to, value: 0n, data: Buffer.from('a') },
      { to, value: 0n, data: Buffer.from('b') },
    ],
  });
  const b = hashTransactionBatch({
    walletId: 'w',
    nonce: 0n,
    deadline: 1n,
    calls: [{ to, value: 0n, data: Buffer.from('ab') }],
  });
  assert.ok(!a.equals(b));
});

test('域分隔：批量摘要不同于普通交易/策略变更摘要，且不含策略版本', () => {
  const [to] = recipients(1);
  const single = { walletId: 'w', nonce: 1n, deadline: 2n, to: to!, value: 5n, data: Buffer.from('d') };
  const tx = hashTransaction(single);
  const batch = hashTransactionBatch({
    walletId: 'w',
    nonce: 1n,
    deadline: 2n,
    calls: [{ to: to!, value: 5n, data: Buffer.from('d') }],
  });
  assert.ok(!tx.equals(batch), '单笔交易摘要与同内容批量摘要必须不同');
  // 不存在任何版本入参：同内容在任意外部版本语境下摘要一致
  assert.ok(hashTransactionBatch(baseBatch()).equals(hashTransactionBatch(baseBatch())));
});

// ---------- 提交成功路径 ----------

test('合法批量提交：只入队一个任务、载荷有序规范化、只消费本次 nonce', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const task = submitBatch(wallet, ownerActors, calls);

  assert.equal(task.status, 'queued');
  assert.equal(task.seq, 0);
  assert.equal(task.nonce, 0n);
  assert.equal(task.payload.kind, 'transaction-batch');
  assert.equal(wallet.tasks.length, 1, '整批只创建一个任务');
  assert.equal(wallet.expectedNonce, 1n, '整批只推进一个 nonce');
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.policyVersion, 1n);

  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls.length, 3);
  assert.deepEqual(
    task.payload.calls.map((c) => c.to),
    calls.map((c) => c.to),
  );
  assert.deepEqual(
    task.payload.calls.map((c) => c.value),
    [10n, 20n, 0n],
  );
  // data 被拷贝为独立字节缓冲，与入参脱钩
  assert.deepEqual(
    task.payload.calls.map((c) => Buffer.from(c.data).toString('hex')),
    ['first', 'second', ''].map((s) => Buffer.from(s).toString('hex')),
  );
});

test('地址与 data 规范化：大写十六进制地址提交后小写保存；Buffer/缺省 data 均接受', () => {
  const { wallet, ownerActors } = setup();
  const [to] = recipients(1);
  // 保持 0x 前缀、仅将十六进制位大写（EIP-55 之外的大写形式）
  const upper = '0x' + to!.slice(2).toUpperCase();
  const params = batchParams([
    { to: upper, value: 1n, data: Buffer.from('x') },
    { to: recipients(1)[0]!, value: 2n },
  ]);
  const sigs = signTransactionBatch(ownerActors.slice(0, 2), params);
  const task = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: 9000n, calls: [{ to: upper, value: 1n, data: Buffer.from('x') }, { to: params.calls[1]!.to, value: 2n }] },
    sigs,
  );
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls[0]!.to, to);
  assert.deepEqual(Buffer.from(task.payload.calls[1]!.data), Buffer.alloc(0));
});

test('调用方在提交后修改入参数组不影响已入队任务（data 拷贝语义）', () => {
  const { wallet, ownerActors } = setup();
  const data = Buffer.from('abc');
  const task = submitBatch(wallet, ownerActors, [{ to: recipients(1)[0]!, value: 1n, data }]);
  data[0] = 0xff;
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.deepEqual(Buffer.from(task.payload.calls[0]!.data).toString('hex'), Buffer.from('abc').toString('hex'));
});

test('64 项调用为合法上限；65 项拒绝', () => {
  const { wallet, ownerActors } = setup();
  const tos = recipients(MAX_BATCH_CALLS + 1);
  const calls64 = tos.slice(0, MAX_BATCH_CALLS).map((to) => ({ to, value: 1n }));
  const task = submitBatch(wallet, ownerActors, calls64);
  assert.equal(task.status, 'queued');
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls.length, MAX_BATCH_CALLS);

  const calls65 = tos.map((to) => ({ to, value: 1n }));
  const sigs65 = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls65, { nonce: 1n }));
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 1n, deadline: 9000n, calls: calls65 },
        sigs65,
      ),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.expectedNonce, 1n);
});

// ---------- 执行 ----------

test('执行批量任务：整批一个 transfer-batch 回执，calls 按输入顺序给出地址/原金额/十六进制 data', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const task = submitBatch(wallet, ownerActors, calls);
  const done = wallet.executeNext();

  assert.equal(done!.id, task.id);
  assert.equal(done!.status, 'executed');
  assert.equal(done!.receipt!.failureReason, null);
  const result = done!.receipt!.result as {
    kind: string;
    calls: { to: string; value: bigint; data: string }[];
  };
  assert.equal(result.kind, 'transfer-batch');
  assert.equal(result.calls.length, 3, '无部分执行回执：一次给出全部调用');
  assert.deepEqual(
    result.calls,
    calls.map((c) => ({ to: c.to, value: c.value, data: Buffer.from(c.data).toString('hex') })),
  );
  // 不触碰策略
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
});

test('终态幂等：重复 executeTask/executeNext 返回同一任务与同一回执，不重复生效', () => {
  const { wallet, ownerActors } = setup();
  const task = submitBatch(wallet, ownerActors, defaultCalls());
  const first = wallet.executeTask(task.id);
  const second = wallet.executeTask(task.id);
  assert.equal(second, first);
  assert.equal(second.status, 'executed');
  assert.equal(second.receipt, first.receipt);
  // 队首已终态：executeNext 越过它，队列排空返回 null
  assert.equal(wallet.executeNext(), null);
});

test('FIFO 不变：批量任务与单笔交易/策略变更交错，仅队首可执行', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;

  // nonce 0：单笔交易
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9500n, to: newbie.address, value: 1n,
  });
  const t0 = wallet.submitTransaction({ nonce: 0n, deadline: 9500n, to: newbie.address, value: 1n }, txSigs);

  // nonce 1：批量交易
  const t1 = submitBatch(wallet, ownerActors, [{ to: newbie.address, value: 2n, data: Buffer.from('aa') }], { nonce: 1n });

  // nonce 2：策略变更（降阈值到 1）
  const newOwners = [ownerActors[0]!.address, newbie.address];
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 2n, deadline: 9500n, newOwners, newConfirmations: 1n,
  });
  const t2 = wallet.proposePolicyChange(
    { version: 1n, nonce: 2n, deadline: 9500n, newOwners, newConfirmations: 1n },
    pcSigs,
  );

  assert.deepEqual(wallet.tasks.map((t) => t.seq), [0, 1, 2]);
  // 越序执行批量任务 → InvalidQueueStateError
  assert.throws(() => wallet.executeTask(t1.id), InvalidQueueStateError);

  const r0 = wallet.executeNext();
  assert.equal(r0!.id, t0.id);
  assert.equal((r0!.receipt!.result as { kind: string }).kind, 'transfer');

  const r1 = wallet.executeTask(t1.id);
  assert.equal(r1.status, 'executed');
  assert.equal((r1.receipt!.result as { kind: string }).kind, 'transfer-batch');

  const r2 = wallet.executeNext();
  assert.equal(r2!.id, t2.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.requiredConfirmations, 1n);

  // 新策略下批量交易只需 1 个当前所有者签名
  const sigs3 = signTransactionBatch([newbie], {
    walletId: WALLET,
    nonce: 3n,
    deadline: 9900n,
    calls: [{ to: ownerActors[0]!.address, value: 9n, data: new Uint8Array() }],
  });
  const t3 = wallet.submitBatchTransaction(
    { nonce: 3n, deadline: 9900n, calls: [{ to: ownerActors[0]!.address, value: 9n }] },
    sigs3,
  );
  const done3 = wallet.executeTask(t3.id);
  assert.equal(done3.status, 'executed');
  assert.equal((done3.receipt!.result as { calls: { value: bigint }[] }).calls[0]!.value, 9n);
});

// ---------- 取消批量任务 ----------

test('cancelTask 可取消尚未执行的批量任务：保留 payload/digest/nonce 与取消记录，无调用结果', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const target = submitBatch(wallet, ownerActors, calls);
  const before = wallet.getTask(target.id)!;

  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET, taskDigest: target.digest, nonce: 1n, deadline: 9000n,
  });
  const cancelled = wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, sigs);

  assert.equal(cancelled.status, 'cancelled');
  assert.deepEqual(cancelled.payload, before.payload);
  assert.equal(cancelled.digest, before.digest);
  assert.equal(cancelled.nonce, 0n);
  assert.equal(cancelled.seq, before.seq);
  assert.equal(cancelled.receipt, undefined, '不产生调用结果');
  assert.equal(cancelled.cancellation!.cancelledAt, 1000n);
  assert.notEqual(cancelled.cancellation!.digest, before.digest);
  // 批量 nonce 与取消 nonce 各算一次；策略不变
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.isNonceUsed(1n), true);
  assert.equal(wallet.expectedNonce, 2n);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));

  // 对 cancelled 批量任务执行直接返回终态；executeNext 越过后队列排空
  assert.equal(wallet.executeTask(target.id).status, 'cancelled');
  assert.equal(wallet.executeNext(), null);
});

test('已执行的批量任务不可再取消（终态冲突）', () => {
  const { wallet, ownerActors } = setup();
  const target = submitBatch(wallet, ownerActors, defaultCalls());
  wallet.executeTask(target.id);
  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET, taskDigest: target.digest, nonce: 1n, deadline: 9000n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, sigs),
    /TaskCancellationConflict/,
  );
  assert.equal(wallet.expectedNonce, 1n);
});

// ---------- 提交校验失败 ----------

test('调用列表为空 / 非数组 / 超过 64 项 → InvalidTransactionBatch，无任何副作用', () => {
  const { wallet, ownerActors } = setup();
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const badLists: unknown[] = [
    undefined,
    null,
    [],
    'not-a-list',
    42,
    {},
    Array.from({ length: MAX_BATCH_CALLS + 1 }, () => ({ to: recipients(1)[0], value: 1n })),
  ];
  for (const calls of badLists) {
    assert.throws(
      () =>
        wallet.submitBatchTransaction(
          { nonce: 0n, deadline: 9000n, calls: calls as never },
          placeholder,
        ),
      InvalidTransactionBatch,
    );
  }
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.policyVersion, 1n);
});

test('收款地址非法或为零、金额越界、data 不是字节数组 → InvalidTransactionBatch', () => {
  const { wallet } = setup();
  const good = recipients(1)[0]!;
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const badCalls: unknown[] = [
    [{ to: '0x123', value: 1n }],
    [{ to: '0x' + '00'.repeat(20), value: 1n }],
    [{ to: 42, value: 1n }],
    [{ to: good, value: -1n }],
    [{ to: good, value: 2n ** 256n }],
    [{ to: good, value: 'abc' }],
    [{ to: good, value: 1n, data: 'deadbeef' }],
    [{ to: good, value: 1n, data: [1, 2, 3] }],
    [null],
    [42],
    [{ to: good }], // 缺 value
    [{ value: 1n }], // 缺 to
  ];
  for (const calls of badCalls) {
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, placeholder),
      InvalidTransactionBatch,
    );
  }
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
});

test('nonce 跳号/回退 → InvalidTransactionBatch；复用 → NonceAlreadyUsedError', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const jumpSigs = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls, { nonce: 5n }));
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 5n, deadline: 9000n, calls: calls as never },
        jumpSigs,
      ),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.expectedNonce, 0n);

  submitBatch(wallet, ownerActors, calls, { nonce: 0n });
  const replaySigs = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls, { nonce: 0n, deadline: 9500n }));
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 9500n, calls: calls as never },
        replaySigs,
      ),
    NonceAlreadyUsedError,
  );
  assert.equal(wallet.tasks.length, 1);
});

test('deadline 早于当前时间 → RequestExpired；边界等于当前时间有效；过期不消费 nonce', () => {
  const { wallet, ownerActors, clock } = setup();
  const calls = defaultCalls();
  const expired = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls, { deadline: 999n }));
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 999n, calls: calls as never },
        expired,
      ),
    RequestExpired,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);

  clock.set(2000n);
  const edge = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls, { deadline: 2000n }));
  const task = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: 2000n, calls: calls as never },
    edge,
  );
  assert.equal(task.status, 'queued');
});

test('已用 nonce 优先于过期判定：旧批量请求重放恒为 NonceAlreadyUsedError', () => {
  const { wallet, ownerActors, clock } = setup();
  const calls = defaultCalls();
  submitBatch(wallet, ownerActors, calls, { nonce: 0n, deadline: 5000n });
  clock.set(9000n);
  const replay = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls, { nonce: 0n, deadline: 5000n }));
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 5000n, calls: calls as never },
        replay,
      ),
    NonceAlreadyUsedError,
  );
});

test('签名集合畸形/非所有者/同人重复签/去重后不足阈值 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const params = batchParams(calls);
  const sub = { nonce: 0n, deadline: 9000n, calls: calls as never };

  assert.throws(() => wallet.submitBatchTransaction(sub, []), InvalidTransactionBatch);
  assert.throws(
    () => wallet.submitBatchTransaction(sub, [new Uint8Array(65), new Uint8Array(65)]),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.submitBatchTransaction(sub, [new Uint8Array(64), new Uint8Array(65)]),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.submitBatchTransaction(sub, signTransactionBatch([ownerActors[0]!], params)),
    InvalidTransactionBatch,
  );
  const outsider = actors(1)[0]!;
  assert.throws(
    () => wallet.submitBatchTransaction(sub, signTransactionBatch([ownerActors[0]!, outsider], params)),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.submitBatchTransaction(sub, signTransactionBatch([ownerActors[0]!, ownerActors[0]!], params)),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
});

test('签名与提交内容不一致：任一调用内容/顺序或钱包标识变化 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const params = batchParams(calls);

  // 为 [c0,c1,c2] 签名，提交调换 c0/c1 顺序
  const swappedSig = signTransactionBatch(ownerActors.slice(0, 2), params);
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 9000n, calls: [calls[1]!, calls[0]!, calls[2]!] as never },
        swappedSig,
      ),
    InvalidTransactionBatch,
  );

  // 修改其中一项的 value / data / to
  const mutations = [
    (p: BatchParams): BatchParams => ({
      ...p,
      calls: [{ ...p.calls[0]!, value: 999n }, p.calls[1]!, p.calls[2]!],
    }),
    (p: BatchParams): BatchParams => ({
      ...p,
      calls: [{ ...p.calls[0]!, data: Buffer.from('tampered') }, p.calls[1]!, p.calls[2]!],
    }),
    (p: BatchParams): BatchParams => ({ ...p, walletId: 'wallet-OTHER' }),
    (p: BatchParams): BatchParams => ({ ...p, nonce: 1n }),
    (p: BatchParams): BatchParams => ({ ...p, deadline: 9001n }),
  ];
  for (const mutate of mutations) {
    const sigs = signTransactionBatch(ownerActors.slice(0, 2), params, { mutate });
    assert.throws(
      () =>
        wallet.submitBatchTransaction(
          { nonce: 0n, deadline: 9000n, calls: calls as never },
          sigs,
        ),
      InvalidTransactionBatch,
    );
  }
  assert.equal(wallet.tasks.length, 0);
});

test('域隔离：单笔交易/策略变更/取消签名均不能授权批量交易，反之亦然', () => {
  const { wallet, ownerActors } = setup();
  const calls = defaultCalls();
  const to = calls[0]!.to;

  // 单笔交易签名 → 批量提交
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9000n, to, value: 10n,
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, txSigs),
    InvalidTransactionBatch,
  );

  // 策略变更签名 → 批量提交
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n,
    newOwners: addresses(ownerActors), newConfirmations: 2n,
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, pcSigs),
    InvalidTransactionBatch,
  );

  // 取消签名 → 批量提交
  const fakeDigest = 'ab'.repeat(32);
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET, taskDigest: fakeDigest, nonce: 0n, deadline: 9000n,
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, cancelSigs),
    InvalidTransactionBatch,
  );

  // 批量签名 → 单笔交易提交（恢复出的签名者不匹配 → InvalidTransaction）
  const batchSigs = signTransactionBatch(ownerActors.slice(0, 2), batchParams(calls));
  assert.throws(
    () => wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 10n }, batchSigs),
    InvalidTransaction,
  );

  // 批量签名 → 取消提交：先建一个真实 queued 任务（nonce 0），取消请求用 nonce 1 到达签名校验
  const decoyTo = actors(1)[0]!.address;
  const decoySigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9000n, to: decoyTo, value: 1n,
  });
  const decoy = wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to: decoyTo, value: 1n }, decoySigs);
  const batchSigsForCancel = signTransactionBatch(
    ownerActors.slice(0, 2),
    batchParams(calls, { nonce: 1n }),
  );
  assert.throws(
    () => wallet.cancelTask({ taskId: decoy.id, nonce: 1n, deadline: 9000n }, batchSigsForCancel),
    InvalidCancellation,
  );

  // 批量签名 → 策略变更提交
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        { version: 1n, nonce: 1n, deadline: 9000n, newOwners: addresses(ownerActors), newConfirmations: 2n },
        batchSigs,
      ),
    InvalidPolicyChange,
  );
  assert.equal(wallet.tasks.length, 1, '所有跨域提交均被拒绝，只有 decoy 入队');
  assert.equal(wallet.expectedNonce, 1n);
});

// ---------- 对抗输入 ----------

test('对抗输入：批量提交路径仅抛出约定错误类型，不泄漏原生 TypeError', () => {
  const { wallet } = setup();
  const EXPECTED = new Set([
    InvalidTransactionBatch.name,
    NonceAlreadyUsedError.name,
    RequestExpired.name,
  ]);
  const to = recipients(1)[0]!;
  const sigs = [new Uint8Array(65), new Uint8Array(65)];
  const garbage: unknown[] = [undefined, null, 'abc', -1.5, Number.NaN, {}, [], 2n ** 300n];

  for (const g of garbage) {
    for (const field of ['nonce', 'deadline'] as const) {
      const sub: Record<string, unknown> = {
        nonce: 0n,
        deadline: 9000n,
        calls: [{ to, value: 1n }],
      };
      sub[field] = g;
      assert.throws(
        () => wallet.submitBatchTransaction(sub as never, sigs),
        (err: unknown) => EXPECTED.has((err as Error).name),
      );
    }
    // 每项中的 value 畸形
    assert.throws(
      () =>
        wallet.submitBatchTransaction(
          { nonce: 0n, deadline: 9000n, calls: [{ to, value: g as never }] },
          sigs,
        ),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
  }

  // 畸形调用列表元素
  for (const calls of [
    [undefined],
    [null],
    ['x'],
    [[]],
    [{}],
    [{ to: '0x123', value: 1n }],
    [{ to: to.toUpperCase().slice(0, 10), value: 1n }],
  ]) {
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, sigs),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
  }

  // 畸形签名集合元素
  for (const badSigs of [[], [null], ['deadbeef'], [new Uint8Array(0)], 'not-an-array']) {
    assert.throws(
      () =>
        wallet.submitBatchTransaction(
          { nonce: 0n, deadline: 9000n, calls: [{ to, value: 1n }] },
          badSigs as never,
        ),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
  }
});
