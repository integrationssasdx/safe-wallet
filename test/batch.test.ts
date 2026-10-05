import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, MAX_BATCH_CALLS, type WalletTask } from '../src/wallet.ts';
import {
  InvalidTransaction,
  InvalidTransactionBatch,
  InvalidPolicyChange,
  InvalidCancellation,
  NonceAlreadyUsedError,
  RequestExpired,
  InvalidQueueStateError,
  TaskCancellationConflict,
} from '../src/errors.ts';
import {
  actors,
  addresses,
  fakeClock,
  signBatchTransaction,
  signCancellation,
  signPolicyChange,
  signTransaction,
  type Actor,
  type BatchParams,
} from './helpers.ts';
import { generateKeyPair } from '../src/crypto.ts';

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

interface CallSpec {
  to: string;
  value: bigint;
  data: Uint8Array;
}

/** n 个合法调用（不同收款方，带 data） */
function makeCalls(n: number, valueStart = 100n): CallSpec[] {
  return Array.from({ length: n }, (_, i) => ({
    to: generateKeyPair().address,
    value: valueStart + BigInt(i),
    data: Buffer.from(`data-${i}`),
  }));
}

function batchParams(
  calls: CallSpec[],
  over: Partial<BatchParams> = {},
): BatchParams {
  return { walletId: WALLET, nonce: 0n, deadline: 9000n, calls, ...over };
}

/** 用前两个所有者签名并提交批量交易 */
function submitBatch(
  wallet: MultiSigWallet,
  ownerActors: Actor[],
  calls: CallSpec[],
  over: { nonce?: bigint; deadline?: bigint; walletId?: string } = {},
): WalletTask {
  const params = batchParams(calls, {
    nonce: over.nonce ?? 0n,
    deadline: over.deadline ?? 9000n,
    walletId: over.walletId ?? WALLET,
  });
  const sigs = signBatchTransaction(ownerActors.slice(0, 2), params);
  return wallet.submitBatchTransaction(
    {
      nonce: params.nonce,
      deadline: params.deadline,
      calls: params.calls.map((c) => ({
        to: c.to,
        value: c.value ?? 0n,
        data: c.data ?? new Uint8Array(),
      })),
    },
    sigs,
  );
}

// ---------- 成功提交 ----------

test('批量：达到阈值 → 只入队一个任务、只消费一个 nonce，调用顺序与内容保留', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(3);
  const task = submitBatch(wallet, ownerActors, calls);

  assert.equal(task.status, 'queued');
  assert.equal(task.seq, 0);
  assert.equal(task.nonce, 0n);
  assert.equal(task.payload.kind, 'transaction-batch');
  assert.equal(wallet.tasks.length, 1, '整批只有一个队列任务');
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.policyVersion, 1n);

  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.deepEqual(
    task.payload.calls.map((c) => c.to),
    calls.map((c) => c.to),
    '顺序不得改变',
  );
  assert.deepEqual(
    task.payload.calls.map((c) => c.value),
    calls.map((c) => c.value),
  );
  assert.deepEqual(
    task.payload.calls.map((c) => Buffer.from(c.data).toString('hex')),
    calls.map((c) => Buffer.from(c.data).toString('hex')),
  );
});

test('批量：边界 64 项允许，空 data 允许，金额允许为 0', () => {
  const { wallet, ownerActors } = setup();
  const calls: CallSpec[] = Array.from({ length: MAX_BATCH_CALLS }, () => ({
    to: generateKeyPair().address,
    value: 0n,
    data: new Uint8Array(),
  }));
  const task = submitBatch(wallet, ownerActors, calls);
  assert.equal(task.status, 'queued');
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls.length, MAX_BATCH_CALLS);
  assert.deepEqual(Buffer.from(task.payload.calls[0]!.data), Buffer.alloc(0));
});

test('批量：收款地址大小写混排 → 规范化为小写，摘要按规范化地址绑定', () => {
  const { wallet, ownerActors } = setup();
  const lower = generateKeyPair().address;
  const upper = '0x' + lower.slice(2).toUpperCase();
  assert.notEqual(upper, lower);
  const calls: CallSpec[] = [{ to: upper, value: 5n, data: Buffer.from('x') }];
  // 签名侧直接用规范化后的小写地址；提交侧给大写，两者必须收敛到同一摘要
  const sigs = signBatchTransaction(
    ownerActors.slice(0, 2),
    batchParams([{ to: lower, value: 5n, data: Buffer.from('x') }]),
  );
  const task = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: 9000n, calls },
    sigs,
  );
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls[0]!.to, lower);
});

test('批量：提交后再改动入参 data 不影响任务（内部持有副本）', () => {
  const { wallet, ownerActors } = setup();
  const data = Buffer.from('original');
  const calls: CallSpec[] = [{ to: generateKeyPair().address, value: 1n, data }];
  const task = submitBatch(wallet, ownerActors, calls);
  data[0] = 0xff; // 外部修改
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(Buffer.from(task.payload.calls[0]!.data).toString(), 'original');
});

// ---------- 执行回执 ----------

test('批量执行：整批成功产生一个 transfer-batch 回执，calls 按输入顺序、十六进制 data', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(4);
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
  assert.equal(result.calls.length, 4);
  assert.deepEqual(
    result.calls,
    calls.map((c) => ({
      to: c.to,
      value: c.value,
      data: Buffer.from(c.data).toString('hex'),
    })),
  );
  // 只有一个回执，没有逐调用的部分回执
  assert.equal(wallet.tasks.filter((t) => t.receipt).length, 1);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
});

test('批量执行：重复执行幂等，返回同一任务与同一回执，不重复生效', () => {
  const { wallet, ownerActors } = setup();
  const task = submitBatch(wallet, ownerActors, makeCalls(2));
  const first = wallet.executeTask(task.id);
  const again = wallet.executeTask(task.id);
  assert.equal(again, first);
  assert.equal(again.status, 'executed');
  assert.equal(again.receipt, first.receipt);
});

test('批量执行不产生部分执行回执：执行结果要么整批一个，要么没有', () => {
  const { wallet, ownerActors } = setup();
  const task = submitBatch(wallet, ownerActors, makeCalls(3));
  // 执行前无任何回执
  assert.equal(task.receipt, undefined);
  wallet.executeTask(task.id);
  const done = wallet.getTask(task.id)!;
  assert.ok(done.receipt);
  assert.equal((done.receipt!.result as { kind: string }).kind, 'transfer-batch');
  assert.equal(done.receipt!.failureReason, null);
});

// ---------- 入参内容校验 ----------

test('批量：列表为空 / 非数组 / 超过 64 项 → InvalidTransactionBatch，无副作用', () => {
  const { wallet } = setup();
  // 列表形状/长度校验先于签名校验，占位签名即可证明
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const bad: unknown[] = [[], undefined, null, 'not-array', 42, {}, makeCalls(MAX_BATCH_CALLS + 1)];
  for (const calls of bad) {
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, placeholder),
      InvalidTransactionBatch,
    );
    assert.equal(wallet.tasks.length, 0);
    assert.equal(wallet.expectedNonce, 0n);
  }
});

test('批量：收款地址非法或为零 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const zero = '0x' + '00'.repeat(20);
  const badLists: unknown[] = [
    [{ to: '0x123', value: 1n, data: new Uint8Array() }],
    [{ to: zero, value: 1n, data: new Uint8Array() }],
    [
      { to: generateKeyPair().address, value: 1n, data: new Uint8Array() },
      { to: 'not-an-address', value: 2n, data: new Uint8Array() },
    ],
    [{ value: 1n, data: new Uint8Array() }],
    [null],
    [42],
    ['just-a-string'],
  ];
  for (const calls of badLists) {
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls: calls as never }, placeholder),
      InvalidTransactionBatch,
    );
  }
  assert.equal(wallet.tasks.length, 0);
});

test('批量：金额越界（负数 / 超过 256 位 / 非数字） → InvalidTransactionBatch', () => {
  const { wallet } = setup();
  const to = generateKeyPair().address;
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const badValues: unknown[] = [-1n, 2n ** 256n, 'abc', 1.5, undefined, null];
  for (const value of badValues) {
    const calls = [{ to, value: value as never, data: new Uint8Array() }];
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, placeholder),
      InvalidTransactionBatch,
    );
  }
});

test('批量：data 不是 Uint8Array → InvalidTransactionBatch（严格类型，字符串/数组均拒绝）', () => {
  const { wallet } = setup();
  const to = generateKeyPair().address;
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  const badData: unknown[] = ['deadbeef', [0xde, 0xad], { length: 0 }, 42, null];
  for (const data of badData) {
    const calls = [{ to, value: 1n, data: data as never }];
    assert.throws(
      () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, placeholder),
      InvalidTransactionBatch,
    );
  }
});

// ---------- nonce / deadline 顺序 ----------

test('批量：nonce 跳号 → InvalidTransactionBatch；已用 nonce → NonceAlreadyUsedError', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(1);

  const skip = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls, { nonce: 5n }));
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 5n, deadline: 9000n, calls }, skip),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.expectedNonce, 0n);

  submitBatch(wallet, ownerActors, calls, { nonce: 0n });
  const replay = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls, { nonce: 0n }));
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, replay),
    NonceAlreadyUsedError,
  );
});

test('批量：deadline 早于当前时间 → RequestExpired；边界相等有效', () => {
  const { wallet, ownerActors, clock } = setup(undefined, undefined, 1000n);
  const calls = makeCalls(1);

  const expired = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls, { deadline: 999n }));
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 999n, calls }, expired),
    RequestExpired,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);

  const edge = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls, { deadline: 1000n }));
  const task = wallet.submitBatchTransaction({ nonce: 0n, deadline: 1000n, calls }, edge);
  assert.equal(task.status, 'queued');
  void clock;
});

test('批量：已用 nonce 优先于过期判定（旧批量请求重放恒为 NonceAlreadyUsedError）', () => {
  const { wallet, ownerActors, clock } = setup();
  const calls = makeCalls(1);
  const sigs = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls, { deadline: 5000n }));
  wallet.submitBatchTransaction({ nonce: 0n, deadline: 5000n, calls }, sigs);
  clock.set(9000n);
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 5000n, calls }, sigs),
    NonceAlreadyUsedError,
  );
});

// ---------- 签名与摘要绑定 ----------

test('批量：签名不足 / 非所有者 / 同人重复签 / 畸形签名 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(2);
  const params = batchParams(calls);
  const sub = { nonce: 0n, deadline: 9000n, calls };

  assert.throws(() => wallet.submitBatchTransaction(sub, []), InvalidTransactionBatch);
  assert.throws(
    () => wallet.submitBatchTransaction(sub, signBatchTransaction([ownerActors[0]!], params)),
    InvalidTransactionBatch,
  );
  const outsider = actors(1)[0]!;
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        sub,
        signBatchTransaction([ownerActors[0]!, outsider], params),
      ),
    InvalidTransactionBatch,
  );
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        sub,
        signBatchTransaction([ownerActors[0]!, ownerActors[0]!], params),
      ),
    InvalidTransactionBatch,
  );
  for (const bad of [[new Uint8Array(64)], [new Uint8Array(65), new Uint8Array(65)], 'sigs']) {
    assert.throws(
      () => wallet.submitBatchTransaction(sub, bad as never),
      InvalidTransactionBatch,
    );
  }
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
});

test('批量摘要：任一调用内容、顺序、项数或绑定字段变化 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(3);
  const params = batchParams(calls);
  const sub = { nonce: 0n, deadline: 9000n, calls };

  const mutateCases: ((p: BatchParams) => BatchParams)[] = [
    (p) => ({ ...p, calls: p.calls.map((c, i) => (i === 1 ? { ...c, value: c.value! + 1n } : c)) }),
    (p) => ({ ...p, calls: p.calls.map((c, i) => (i === 0 ? { ...c, data: Buffer.from('changed') } : c)) }),
    (p) => ({
      ...p,
      calls: p.calls.map((c, i) => (i === 2 ? { ...c, to: generateKeyPair().address } : c)),
    }),
    // 交换两个调用的顺序
    (p) => ({ ...p, calls: [p.calls[1]!, p.calls[0]!, p.calls[2]!] }),
    // 去掉一项（项数变化）
    (p) => ({ ...p, calls: [p.calls[0]!, p.calls[1]!] }),
    // 追加一项
    (p) => ({ ...p, calls: [...p.calls, { to: generateKeyPair().address, value: 999n, data: new Uint8Array() }] }),
    (p) => ({ ...p, nonce: 1n }),
    (p) => ({ ...p, deadline: 8000n }),
    (p) => ({ ...p, walletId: 'wallet-OTHER' }),
  ];
  for (const mutate of mutateCases) {
    const sigs = signBatchTransaction(ownerActors.slice(0, 2), params, { mutate });
    assert.throws(() => wallet.submitBatchTransaction(sub, sigs), InvalidTransactionBatch);
  }
  assert.equal(wallet.tasks.length, 0);
});

test('域分隔：单笔/策略变更/取消签名不能授权批量，批量签名也不能授权单笔', () => {
  const { wallet, ownerActors } = setup();
  const to = generateKeyPair().address;
  const calls: CallSpec[] = [{ to, value: 10n, data: Buffer.from('a') }];

  // 单笔交易签名（同 nonce/deadline/收款方/金额/data）用于批量
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to,
    value: 10n,
    data: Buffer.from('a'),
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, txSigs),
    InvalidTransactionBatch,
  );

  // 策略变更签名用于批量
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, pcSigs),
    InvalidTransactionBatch,
  );

  // 批量签名用于单笔交易（即使批量只有一笔、字段完全一致）
  const batchSigs = signBatchTransaction(ownerActors.slice(0, 2), batchParams(calls));
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 0n, deadline: 9000n, to, value: 10n, data: Buffer.from('a') },
        batchSigs,
      ),
    InvalidTransaction,
  );
  assert.equal(wallet.tasks.length, 0);
});

test('取消签名不能用于批量（safe-wallet/cancel/v1 域隔离）', () => {
  const { wallet, ownerActors } = setup();
  // 先放一个任务作为取消摘要目标
  const seeded = submitBatch(wallet, ownerActors, makeCalls(1));
  const calls: CallSpec[] = [{ to: generateKeyPair().address, value: 1n, data: new Uint8Array() }];
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: seeded.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 1n, deadline: 9000n, calls }, cancelSigs),
    InvalidTransactionBatch,
  );
});

// ---------- 取消批量任务 ----------

test('取消批量任务：queued → cancelled，保留 payload/digest/nonce 与取消记录，无回执、策略不变', () => {
  const { wallet, ownerActors } = setup();
  const target = submitBatch(wallet, ownerActors, makeCalls(3), { nonce: 0n });
  const before = wallet.getTask(target.id)!;

  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: target.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  const cancelled = wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, sigs);

  assert.equal(cancelled.status, 'cancelled');
  assert.deepEqual(cancelled.payload, before.payload);
  assert.equal(cancelled.digest, before.digest);
  assert.equal(cancelled.nonce, 0n);
  assert.equal(cancelled.receipt, undefined, '不产生调用结果');
  assert.equal(cancelled.cancellation!.cancelledAt, 1000n);
  assert.notEqual(cancelled.cancellation!.digest, before.digest);
  assert.equal(wallet.isNonceUsed(1n), true);
  assert.equal(wallet.expectedNonce, 2n);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
});

test('已执行的批量任务不可取消；executeTask 对已取消批量任务直接返回终态', () => {
  const { wallet, ownerActors } = setup();
  const target = submitBatch(wallet, ownerActors, makeCalls(2));
  wallet.executeTask(target.id);
  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: target.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, sigs),
    TaskCancellationConflict,
  );

  // 另一批量任务取消后再执行：直接 cancelled，无 transfer-batch 回执
  const t2 = submitBatch(wallet, ownerActors, makeCalls(1), { nonce: 1n });
  const cancel2 = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: t2.digest,
    nonce: 2n,
    deadline: 9000n,
  });
  wallet.cancelTask({ taskId: t2.id, nonce: 2n, deadline: 9000n }, cancel2);
  const viewed = wallet.executeTask(t2.id);
  assert.equal(viewed.status, 'cancelled');
  assert.equal(viewed.receipt, undefined);
});

// ---------- FIFO 交互 ----------

test('FIFO：批量任务与单笔/策略变更交错提交，按序执行，越序被拒', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const newbie = actors(1)[0]!;

  // nonce 0：单笔
  const to0 = newbie.address;
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9500n, to: to0, value: 10n, data: new Uint8Array(),
  });
  const t0 = wallet.submitTransaction({ nonce: 0n, deadline: 9500n, to: to0, value: 10n }, txSigs);

  // nonce 1：批量（2 项）
  const t1 = submitBatch(wallet, ownerActors, makeCalls(2, 20n), { nonce: 1n, deadline: 9500n });

  // 越序执行 t1 被拒
  assert.throws(() => wallet.executeTask(t1.id), InvalidQueueStateError);

  const r0 = wallet.executeNext();
  assert.equal(r0!.id, t0.id);
  assert.equal((r0!.receipt!.result as { kind: string }).kind, 'transfer');

  const r1 = wallet.executeNext();
  assert.equal(r1!.id, t1.id);
  const result = r1!.receipt!.result as { kind: string; calls: unknown[] };
  assert.equal(result.kind, 'transfer-batch');
  assert.equal(result.calls.length, 2);

  // nonce 2：策略变更降阈值到 1
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 2n, deadline: 9500n, newOwners: ownersA, newConfirmations: 1n,
  });
  const t2 = wallet.proposePolicyChange(
    { version: 1n, nonce: 2n, deadline: 9500n, newOwners: ownersA, newConfirmations: 1n },
    pcSigs,
  );
  const r2 = wallet.executeNext();
  assert.equal(r2!.id, t2.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.requiredConfirmations, 1n);

  // 新策略：nonce 3 批量只需 newbie 单签
  const calls3 = makeCalls(1, 1n);
  const sigs3 = signBatchTransaction([newbie], batchParams(calls3, { nonce: 3n, deadline: 9500n }));
  const t3 = wallet.submitBatchTransaction(
    { nonce: 3n, deadline: 9500n, calls: calls3 },
    sigs3,
  );
  const done3 = wallet.executeNext();
  assert.equal(done3!.id, t3.id);
  assert.equal(done3!.status, 'executed');
  assert.equal(wallet.expectedNonce, 4n);
});

test('executeNext 越过队首 cancelled 的批量任务；全终态返回 null', () => {
  const { wallet, ownerActors } = setup();
  const tb = submitBatch(wallet, ownerActors, makeCalls(2), { nonce: 0n });
  const tx_to = generateKeyPair().address;
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 1n, deadline: 9000n, to: tx_to, value: 7n, data: new Uint8Array(),
  });
  const tTx = wallet.submitTransaction({ nonce: 1n, deadline: 9000n, to: tx_to, value: 7n }, txSigs);

  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET, taskDigest: tb.digest, nonce: 2n, deadline: 9000n,
  });
  wallet.cancelTask({ taskId: tb.id, nonce: 2n, deadline: 9000n }, cancelSigs);

  const done = wallet.executeNext();
  assert.equal(done!.id, tTx.id);
  assert.equal((done!.receipt!.result as { kind: string }).kind, 'transfer');
  assert.equal(wallet.executeNext(), null);
});

// ---------- 既有操作兼容（摘要/结果不变） ----------

test('单笔交易摘要与执行结果不因批量特性改变；批量摘要域独立', async () => {
  const { hashTransaction, hashTransactionBatch } = await import('../src/encoding.ts');
  const to = generateKeyPair().address;
  const data = Buffer.from('zz');
  const txDigest = hashTransaction({
    walletId: WALLET, nonce: 0n, deadline: 9000n, to, value: 5n, data,
  });
  const batchDigest = hashTransactionBatch({
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    calls: [{ to, value: 5n, data }],
  });
  assert.ok(!txDigest.equals(batchDigest), '单笔与单元素批量摘要必须不同（域分隔）');

  // 普通交易不含策略版本的既有语义仍成立（同内容摘要稳定）
  assert.ok(
    txDigest.equals(hashTransaction({ walletId: WALLET, nonce: 0n, deadline: 9000n, to, value: 5n, data })),
  );
});

test('失败时不创建任务、不消费 nonce、不改变策略或队列', () => {
  const { wallet, ownerActors } = setup();
  const good = makeCalls(1);
  // 非法内容（空列表）
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 9000n, calls: [] },
        [new Uint8Array(65), new Uint8Array(65)],
      ),
    InvalidTransactionBatch,
  );
  // 非法签名（阈值不足）
  const params = batchParams(good);
  assert.throws(
    () =>
      wallet.submitBatchTransaction(
        { nonce: 0n, deadline: 9000n, calls: good },
        signBatchTransaction([ownerActors[0]!], params),
      ),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.queue.size, 0);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
});

// ---------- 对抗输入 ----------

test('对抗输入：批量提交仅抛出约定错误类型', () => {
  const { wallet } = setup();
  const EXPECTED = new Set([
    InvalidTransactionBatch.name,
    InvalidTransaction.name,
    InvalidPolicyChange.name,
    InvalidCancellation.name,
    NonceAlreadyUsedError.name,
    RequestExpired.name,
  ]);
  const to = generateKeyPair().address;
  const sigs = [new Uint8Array(65), new Uint8Array(65)];
  const garbage: unknown[] = [undefined, null, 'abc', -1.5, {}, [], 2n ** 300n];

  // 顶层标量字段
  for (const g of garbage) {
    for (const field of ['nonce', 'deadline'] as const) {
      const sub: Record<string, unknown> = {
        nonce: 0n,
        deadline: 5000n,
        calls: [{ to, value: 1n, data: new Uint8Array() }],
      };
      sub[field] = g;
      assert.throws(
        () => wallet.submitBatchTransaction(sub as never, sigs),
        (err: unknown) => EXPECTED.has((err as Error).name),
      );
    }
  }
  // calls 与调用内字段畸形
  const badCalls: unknown[] = [
    undefined,
    null,
    'x',
    42,
    {},
    [],
    [null],
    [42],
    [{ to: 123, value: 1n, data: new Uint8Array() }],
    [{ to, value: 'x', data: new Uint8Array() }],
    [{ to, value: -1n, data: new Uint8Array() }],
    [{ to, value: 1n, data: 'hex' }],
    [{ to, value: 1n, data: [1, 2] }],
  ];
  for (const calls of badCalls) {
    assert.throws(
      () =>
        wallet.submitBatchTransaction(
          { nonce: 0n, deadline: 5000n, calls: calls as never },
          sigs,
        ),
      (err: unknown) => EXPECTED.has((err as Error).name),
    );
  }
});
