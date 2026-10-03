import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, type WalletTask } from '../src/wallet.ts';
import {
  InvalidCancellation,
  NonceAlreadyUsedError,
  RequestExpired,
  TaskCancellationConflict,
  TaskNotFoundError,
} from '../src/errors.ts';
import {
  actors,
  addresses,
  fakeClock,
  signCancellation,
  signPolicyChange,
  signTransaction,
  type Actor,
} from './helpers.ts';
import { generateKeyPair } from '../src/crypto.ts';

const WALLET = 'wallet-cancel';

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

/** 提交一笔普通交易并返回任务（消耗一个 nonce） */
function submitTx(wallet: MultiSigWallet, ownerActors: Actor[], nonce: bigint, value = 1n): WalletTask {
  const to = generateKeyPair().address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce,
    deadline: 9000n,
    to,
    value,
  });
  return wallet.submitTransaction({ nonce, deadline: 9000n, to, value }, sigs);
}

/** 针对 target 构造合法取消签名（nonce/deadline 可覆盖） */
function cancelSigs(
  ownerActors: Actor[],
  target: WalletTask,
  nonce: bigint,
  deadline = 9000n,
  mutate?: (p: { walletId: string; taskDigest: string; nonce: bigint; deadline: bigint }) => {
    walletId: string;
    taskDigest: string;
    nonce: bigint;
    deadline: bigint;
  },
) {
  const params = { walletId: WALLET, taskDigest: target.digest, nonce, deadline };
  return signCancellation(ownerActors.slice(0, 2), params, mutate ? { mutate } : {});
}

// ---------- 成功路径 ----------

test('取消成功：queued → cancelled 终态，保留原 payload/digest/nonce，记录取消时间与摘要', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n, 100n);
  const before = wallet.getTask(target.id)!;

  const sigs = cancelSigs(ownerActors, before, 1n);
  const cancelled = wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, sigs);

  assert.equal(cancelled.status, 'cancelled');
  // 原内容保留
  assert.deepEqual(cancelled.payload, before.payload);
  assert.equal(cancelled.digest, before.digest);
  assert.equal(cancelled.nonce, 0n);
  assert.equal(cancelled.seq, before.seq);
  // 取消记录
  assert.equal(cancelled.cancellation!.cancelledAt, 1000n);
  assert.equal(typeof cancelled.cancellation!.digest, 'string');
  assert.notEqual(cancelled.cancellation!.digest, before.digest);
  // 无执行回执（未产生效果）
  assert.equal(cancelled.receipt, undefined);
  // 只消费本次 nonce 并推进 expectedNonce
  assert.equal(wallet.isNonceUsed(1n), true);
  assert.equal(wallet.expectedNonce, 2n);
  // 策略不变、版本不递增
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
  // 快照可见终态
  assert.equal(wallet.getTask(target.id)!.status, 'cancelled');
});

test('取消支持位置参数形式 cancelTask(taskId, nonce, deadline, signatures)', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  const sigs = cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n);
  const cancelled = wallet.cancelTask(target.id, 1n, 9000n, sigs);
  assert.equal(cancelled.status, 'cancelled');
});

test('取消不要求任务在队首，也不调整队列顺序', () => {
  const { wallet, ownerActors } = setup();
  const t0 = submitTx(wallet, ownerActors, 0n);
  const t1 = submitTx(wallet, ownerActors, 1n);
  const t2 = submitTx(wallet, ownerActors, 2n);

  // 取消队列中间的 t1（队首是 t0）
  const sigs = cancelSigs(ownerActors, wallet.getTask(t1.id)!, 3n);
  wallet.cancelTask({ taskId: t1.id, nonce: 3n, deadline: 9000n }, sigs);

  assert.deepEqual(
    wallet.tasks.map((t) => t.id),
    [t0.id, t1.id, t2.id],
    '队列顺序不变',
  );
  assert.deepEqual(
    wallet.tasks.map((t) => t.status),
    ['queued', 'cancelled', 'queued'],
  );
});

// ---------- 目标状态错误 ----------

test('目标不存在 → TaskNotFoundError，无副作用', () => {
  const { wallet, ownerActors } = setup();
  submitTx(wallet, ownerActors, 0n);
  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: 'ab'.repeat(32),
    nonce: 1n,
    deadline: 9000n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: 'no-such-task', nonce: 1n, deadline: 9000n }, sigs),
    TaskNotFoundError,
  );
  assert.equal(wallet.expectedNonce, 1n, '不消费 nonce');
  assert.equal(wallet.isNonceUsed(1n), false);
});

test('目标已 executed / failed / cancelled → TaskCancellationConflict', () => {
  const { wallet, ownerActors } = setup();
  const t0 = submitTx(wallet, ownerActors, 0n);
  const t1 = submitTx(wallet, ownerActors, 1n);
  const t2 = submitTx(wallet, ownerActors, 2n);

  // executed：t0 正常执行
  wallet.executeTask(t0.id);
  // cancelled：t1 先被取消（消耗 nonce 3）
  wallet.cancelTask({ taskId: t1.id, nonce: 3n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(t1.id)!, 3n));
  // failed：构造两个绑定 version=1 的策略变更，前者执行成功（版本 → 2），后者漂移失败
  const newbie = actors(1)[0]!;
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 4n,
    deadline: 9000n,
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });
  const pc = wallet.proposePolicyChange(
    { version: 1n, nonce: 4n, deadline: 9000n, newOwners: [ownerActors[0]!.address, newbie.address], newConfirmations: 1n },
    pcSigs,
  );
  const pc2Sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 5n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  const pc2 = wallet.proposePolicyChange(
    { version: 1n, nonce: 5n, deadline: 9000n, newOwners: addresses(ownerActors), newConfirmations: 2n },
    pc2Sigs,
  );
  wallet.executeTask(t2.id); // 普通交易执行
  wallet.executeTask(pc.id); // 版本 → 2
  wallet.executeTask(pc2.id); // 版本漂移 → failed
  assert.equal(wallet.getTask(pc2.id)!.status, 'failed');

  // 对三类终态目标取消均冲突（冲突判定先于签名校验，签名形式不重要）
  const targets = [t0.id, t1.id, pc2.id];
  for (const id of targets) {
    const task = wallet.getTask(id)!;
    const sigs = signCancellation(ownerActors.slice(0, 2), {
      walletId: WALLET,
      taskDigest: task.digest,
      nonce: 6n,
      deadline: 9000n,
    });
    assert.throws(
      () => wallet.cancelTask({ taskId: id, nonce: 6n, deadline: 9000n }, sigs),
      TaskCancellationConflict,
    );
  }
  assert.equal(wallet.expectedNonce, 6n, '冲突不消费 nonce');
  assert.equal(wallet.policyVersion, 2n, '冲突不改变版本');
});

// ---------- 请求校验错误 ----------

test('字段非法（nonce/deadline/taskId 畸形）→ InvalidCancellation，不消费 nonce', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  const sigs = cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n);

  const bad: Record<string, unknown>[] = [
    { taskId: target.id, nonce: 'abc', deadline: 9000n },
    { taskId: target.id, nonce: -1n, deadline: 9000n },
    { taskId: target.id, nonce: 2n ** 300n, deadline: 9000n },
    { taskId: target.id, nonce: 1n, deadline: 'x' },
    { taskId: target.id, nonce: 1n, deadline: -5n },
    { taskId: '', nonce: 1n, deadline: 9000n },
    { taskId: 42, nonce: 1n, deadline: 9000n },
  ];
  for (const sub of bad) {
    assert.throws(() => wallet.cancelTask(sub as never, sigs), InvalidCancellation);
  }
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
});

test('nonce 跳号 → InvalidCancellation；已用 nonce → NonceAlreadyUsedError', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n);

  // 跳号：期望 1，给 5
  const future = cancelSigs(ownerActors, wallet.getTask(target.id)!, 5n);
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 5n, deadline: 9000n }, future),
    InvalidCancellation,
  );

  // 已用 nonce=0（被目标交易消费）
  const used = cancelSigs(ownerActors, wallet.getTask(target.id)!, 0n);
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 0n, deadline: 9000n }, used),
    NonceAlreadyUsedError,
  );
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
});

test('deadline 早于当前时间 → RequestExpired；边界等于当前时间有效', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  clock.set(2000n);

  const expired = cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n, 1999n);
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 1999n }, expired),
    RequestExpired,
  );
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);

  const edge = cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n, 2000n);
  const cancelled = wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 2000n }, edge);
  assert.equal(cancelled.status, 'cancelled');
});

test('旧取消请求重放：即使已过期也恒为 NonceAlreadyUsedError', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  const sigs = cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n, 3000n);
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 3000n }, sigs);

  clock.set(9999n); // 远超取消请求的 deadline
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 3000n }, sigs),
    NonceAlreadyUsedError,
  );
});

test('签名问题：畸形/非所有者/去重后不足阈值/载荷不一致 → InvalidCancellation', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  const task = wallet.getTask(target.id)!;
  const sub = { taskId: target.id, nonce: 1n, deadline: 9000n };

  // 空签名集合 / 畸形签名
  assert.throws(() => wallet.cancelTask(sub, []), InvalidCancellation);
  assert.throws(() => wallet.cancelTask(sub, [new Uint8Array(65), new Uint8Array(65)]), InvalidCancellation);
  assert.throws(() => wallet.cancelTask(sub, [new Uint8Array(64)]), InvalidCancellation);

  // 非所有者签名
  const outsider = actors(1)[0]!;
  const foreign = signCancellation([ownerActors[0]!, outsider], {
    walletId: WALLET,
    taskDigest: task.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  assert.throws(() => wallet.cancelTask(sub, foreign), InvalidCancellation);

  // 同一所有者重复签名，去重后不足阈值
  const dup = signCancellation([ownerActors[0]!, ownerActors[0]!], {
    walletId: WALLET,
    taskDigest: task.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  assert.throws(() => wallet.cancelTask(sub, dup), InvalidCancellation);

  // 签名载荷与提交内容不一致：nonce / deadline / 目标 digest / 钱包标识 任一改动
  const params = { walletId: WALLET, taskDigest: task.digest, nonce: 1n, deadline: 9000n };
  const mutations = [
    (p: typeof params) => ({ ...p, nonce: 2n }),
    (p: typeof params) => ({ ...p, deadline: 8000n }),
    (p: typeof params) => ({ ...p, taskDigest: 'ff'.repeat(32) }),
    (p: typeof params) => ({ ...p, walletId: 'wallet-OTHER' }),
  ];
  for (const mutate of mutations) {
    const sigs = signCancellation(ownerActors.slice(0, 2), params, { mutate });
    assert.throws(() => wallet.cancelTask(sub, sigs), InvalidCancellation);
  }

  // 全部失败无副作用
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.policyVersion, 1n);
});

test('取消签名不可改绑其他任务：为任务 A 签的取消不能用于任务 B', () => {
  const { wallet, ownerActors } = setup();
  const tA = submitTx(wallet, ownerActors, 0n);
  const tB = submitTx(wallet, ownerActors, 1n);
  // 签名绑定 tA 的 digest，提交目标却是 tB
  const sigs = cancelSigs(ownerActors, wallet.getTask(tA.id)!, 2n);
  assert.throws(
    () => wallet.cancelTask({ taskId: tB.id, nonce: 2n, deadline: 9000n }, sigs),
    InvalidCancellation,
  );
  assert.equal(wallet.getTask(tB.id)!.status, 'queued');
});

test('交易/策略变更签名不能用于取消（域标签隔离）', () => {
  const { wallet, ownerActors } = setup();
  const target = submitTx(wallet, ownerActors, 0n);
  const to = generateKeyPair().address;
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 1n,
    deadline: 9000n,
    to,
    value: 0n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, txSigs),
    InvalidCancellation,
  );
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 1n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, pcSigs),
    InvalidCancellation,
  );
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
});

// ---------- 与执行语义的交互 ----------

test('executeTask 对 cancelled 任务直接返回终态，不产生效果', () => {
  const { wallet, ownerActors } = setup();
  const to = generateKeyPair().address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to,
    value: 777n,
  });
  const target = wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 777n }, sigs);
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(target.id)!, 1n));

  const result = wallet.executeTask(target.id);
  assert.equal(result.status, 'cancelled');
  assert.equal(result.receipt, undefined, '不产生执行回执/效果');
  // 幂等：再次执行仍返回同一终态
  assert.equal(wallet.executeTask(target.id).status, 'cancelled');
});

test('executeNext 越过队首（或连续）cancelled 任务，执行首个 queued；全终态返回 null', () => {
  const { wallet, ownerActors } = setup();
  const t0 = submitTx(wallet, ownerActors, 0n, 10n);
  const t1 = submitTx(wallet, ownerActors, 1n, 20n);
  const t2 = submitTx(wallet, ownerActors, 2n, 30n);

  // 取消队首 t0 与紧随的 t1（nonce 3、4）
  wallet.cancelTask({ taskId: t0.id, nonce: 3n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(t0.id)!, 3n));
  wallet.cancelTask({ taskId: t1.id, nonce: 4n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(t1.id)!, 4n));

  // executeNext 越过两个 cancelled，执行 t2
  const done = wallet.executeNext();
  assert.equal(done!.id, t2.id);
  assert.equal(done!.status, 'executed');
  assert.deepEqual((done!.receipt!.result as { value: bigint }).value, 30n);

  // 剩余全是终态 → null
  assert.equal(wallet.executeNext(), null);
});

test('取消不递增策略版本；只有策略变更成功执行才递增', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  // nonce 0：策略变更任务入队
  const newOwners = [ownerActors[0]!.address, newbie.address];
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners,
    newConfirmations: 1n,
  });
  const pc = wallet.proposePolicyChange(
    { version: 1n, nonce: 0n, deadline: 9000n, newOwners, newConfirmations: 1n },
    pcSigs,
  );
  // nonce 1：普通交易，随后被取消（nonce 2）
  const tx = submitTx(wallet, ownerActors, 1n);
  wallet.cancelTask({ taskId: tx.id, nonce: 2n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(tx.id)!, 2n));
  assert.equal(wallet.policyVersion, 1n, '取消不递增版本');

  // 执行策略变更：队首 pc 仍 queued（取消的 tx 在其后），版本 → 2
  const done = wallet.executeTask(pc.id);
  assert.equal(done.status, 'executed');
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, newOwners);
});

test('取消后 nonce 序列连续推进：后续提交/取消照常工作', () => {
  const { wallet, ownerActors } = setup();
  const t0 = submitTx(wallet, ownerActors, 0n);
  wallet.cancelTask({ taskId: t0.id, nonce: 1n, deadline: 9000n }, cancelSigs(ownerActors, wallet.getTask(t0.id)!, 1n));
  assert.equal(wallet.expectedNonce, 2n);

  // 下一笔交易使用 nonce 2 正常入队、执行
  const t2 = submitTx(wallet, ownerActors, 2n, 42n);
  const done = wallet.executeNext(); // 越过 cancelled 的 t0
  assert.equal(done!.id, t2.id);
  assert.equal(done!.status, 'executed');
});
