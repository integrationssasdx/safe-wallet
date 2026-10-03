import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import { PolicyConflict, RequestExpired, TaskNotFoundError, InvalidQueueStateError } from '../src/errors.ts';
import { actors, addresses, fakeClock, signPolicyChange, signTransaction } from './helpers.ts';

const WALLET = 'wallet-exec';

function setup(ownerCount = 3, confirmations = 2n) {
  const ownerActors = actors(ownerCount);
  const clock = fakeClock(1000n);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations,
    now: clock.now,
  });
  return { ownerActors, clock, wallet };
}

function propose(wallet: MultiSigWallet, ownerActors: ReturnType<typeof actors>, opts: {
  nonce: bigint;
  version?: bigint;
  deadline?: bigint;
  newOwners: string[];
  newConfirmations: bigint;
}) {
  const version = opts.version ?? 1n;
  const deadline = opts.deadline ?? 5000n;
  const sigs = signPolicyChange(ownerActors.slice(0, Number(2)), {
    walletId: WALLET,
    version,
    nonce: opts.nonce,
    deadline,
    newOwners: opts.newOwners,
    newConfirmations: opts.newConfirmations,
  });
  return wallet.proposePolicyChange(
    { version, nonce: opts.nonce, deadline, newOwners: opts.newOwners, newConfirmations: opts.newConfirmations },
    sigs,
  );
}

test('策略变更执行成功：所有者与确认数同时替换，版本恰好递增一次', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];

  const task = propose(wallet, ownerActors, { nonce: 0n, newOwners, newConfirmations: 1n });
  const done = wallet.executeTask(task.id);

  assert.equal(done.status, 'executed');
  assert.deepEqual(done.receipt!.failureReason, null);
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, newOwners);
  assert.equal(wallet.requiredConfirmations, 1n);
  // 旧所有者退出、新所有者生效
  assert.equal(wallet.isOwner(ownerActors[1]!.address), false);
  assert.equal(wallet.isOwner(newbie.address), true);
});

test('原子替换：newOwners 与 newConfirmations 来自同一提案，无中间态可读', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[2]!.address, newbie.address];
  const task = propose(wallet, ownerActors, { nonce: 0n, newOwners, newConfirmations: 2n });
  // 执行前仍是旧策略
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.equal(wallet.isOwner(newbie.address), false);
  wallet.executeTask(task.id);
  assert.deepEqual(wallet.currentOwners, newOwners);
  assert.equal(wallet.requiredConfirmations, 2n);
});

test('成功后进入既有执行终态：重复执行幂等，不再改变策略/版本', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];
  const task = propose(wallet, ownerActors, { nonce: 0n, newOwners, newConfirmations: 1n });
  wallet.executeTask(task.id);
  const again = wallet.executeTask(task.id);
  assert.equal(again.status, 'executed');
  assert.equal(wallet.policyVersion, 2n, '版本不得再次递增');
});

test('版本漂移：先执行另一个策略变更，旧任务执行 → PolicyConflict 失败终态，策略不变', () => {
  const { wallet, ownerActors } = setup(3, 2n);

  // 提案 A（排在队首）：把阈值降为 1，所有者换成 [o0, newbie]
  const newbie = actors(1)[0]!;
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const taskA = propose(wallet, ownerActors, { nonce: 0n, newOwners: ownersA, newConfirmations: 1n });

  // 人为构造“绑定旧版本但排在 A 之后”的任务 B：
  // A 先执行后版本变为 2；B 仍绑定 version=1。
  // 用当前所有者为 B 收集签名（提交时版本仍为 1，合法）。
  const ownersB = [ownerActors[0]!.address, ownerActors[2]!.address];
  const sigsB = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 1n,
    deadline: 6000n,
    newOwners: ownersB,
    newConfirmations: 2n,
  });
  const taskB = wallet.proposePolicyChange(
    { version: 1n, nonce: 1n, deadline: 6000n, newOwners: ownersB, newConfirmations: 2n },
    sigsB,
  );

  // 执行 A：成功，版本 -> 2
  wallet.executeTask(taskA.id);
  assert.equal(wallet.policyVersion, 2n);

  // 执行 B：绑定版本 1 ≠ 当前 2 → PolicyConflict
  const resultB = wallet.executeTask(taskB.id);
  assert.equal(resultB.status, 'failed');
  assert.equal(resultB.receipt!.failureReason, 'PolicyConflict');
  // 策略保持 A 的结果，不被 B 改动，版本不再递增
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, ownersA);
  assert.equal(wallet.requiredConfirmations, 1n);

  // 失败终态幂等：再次执行不重放
  const again = wallet.executeTask(taskB.id);
  assert.equal(again, resultB);
  assert.equal(wallet.policyVersion, 2n);
});

test('PolicyConflict 任务仍占用其 nonce（不回滚 nonce 消费），队列继续向后推进', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const newbie = actors(1)[0]!;
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const taskA = propose(wallet, ownerActors, { nonce: 0n, newOwners: ownersA, newConfirmations: 1n });
  const ownersB = [ownerActors[0]!.address, ownerActors[2]!.address];
  const sigsB = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 1n, deadline: 6000n, newOwners: ownersB, newConfirmations: 2n,
  });
  const taskB = wallet.proposePolicyChange(
    { version: 1n, nonce: 1n, deadline: 6000n, newOwners: ownersB, newConfirmations: 2n },
    sigsB,
  );
  wallet.executeTask(taskA.id);
  wallet.executeTask(taskB.id); // PolicyConflict
  assert.equal(wallet.isNonceUsed(1n), true);
  assert.equal(wallet.expectedNonce, 2n);

  // 后续任务（在新策略下，仅需 newbie 或 o0 单签）可继续提交执行
  const ownersC = [newbie.address];
  const sigsC = signPolicyChange([newbie], {
    walletId: WALLET, version: 2n, nonce: 2n, deadline: 8000n, newOwners: ownersC, newConfirmations: 1n,
  });
  const taskC = wallet.proposePolicyChange(
    { version: 2n, nonce: 2n, deadline: 8000n, newOwners: ownersC, newConfirmations: 1n },
    sigsC,
  );
  const doneC = wallet.executeTask(taskC.id);
  assert.equal(doneC.status, 'executed');
  assert.equal(wallet.policyVersion, 3n);
  assert.deepEqual(wallet.currentOwners, ownersC);
});

test('旧版本/旧签名在版本递增后无法再次生效：重放提案被 InvalidPolicyChange 拒绝', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const newbie = actors(1)[0]!;
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const taskA = propose(wallet, ownerActors, { nonce: 0n, newOwners: ownersA, newConfirmations: 1n });
  wallet.executeTask(taskA.id);
  assert.equal(wallet.policyVersion, 2n);

  // 重新提交一个仍绑定 version=1 的提案 → 版本不匹配
  const replayOwners = [ownerActors[0]!.address, newbie.address];
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 1n, deadline: 9000n, newOwners: replayOwners, newConfirmations: 1n,
  });
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        { version: 1n, nonce: 1n, deadline: 9000n, newOwners: replayOwners, newConfirmations: 1n },
        sigs,
      ),
    /InvalidPolicyChange|PolicyConflict/,
  );
});

test('截止时间只在提交阶段核对：入队后即使超过截止时间才执行，任务仍照常生效', () => {
  const { wallet, ownerActors, clock } = setup(3, 2n);
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];
  // deadline=2000，当前时钟 1000：提交合法并入队
  const task = propose(wallet, ownerActors, { nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 1n });
  clock.set(3000n); // 推进到过期后才执行
  const done = wallet.executeTask(task.id);
  // 规格：执行生效条件穷尽为“版本仍相等 且 队列允许”，deadline 不是执行闸门
  assert.equal(done.status, 'executed');
  assert.equal(done.receipt!.failureReason, null);
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, newOwners);
});

test('过期只能在提交阶段拦截：当前时间已过截止时间的提交报 RequestExpired', () => {
  const { wallet, ownerActors, clock } = setup(3, 2n);
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];
  clock.set(3000n);
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 1n,
  });
  assert.throws(
    () => wallet.proposePolicyChange(
      { version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 1n },
      sigs,
    ),
    RequestExpired,
  );
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.tasks.length, 0);
});

test('不存在任务 id → TaskNotFoundError', () => {
  const { wallet } = setup();
  assert.throws(() => wallet.executeTask('deadbeef'), TaskNotFoundError);
});

test('只能执行队首：队列中有前序任务时，后续任务不能先执行', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const newbie = actors(1)[0]!;
  const t0 = propose(wallet, ownerActors, {
    nonce: 0n, newOwners: [ownerActors[0]!.address, newbie.address], newConfirmations: 1n,
  });
  const t1 = propose(wallet, ownerActors, {
    nonce: 1n, version: 1n, newOwners: addresses(ownerActors), newConfirmations: 2n,
  });
  assert.throws(() => wallet.executeTask(t1.id), InvalidQueueStateError);
  wallet.executeTask(t0.id); // 排空队首后
  assert.doesNotThrow(() => wallet.executeTask(t1.id));
});

test('普通交易执行结果保持既有行为：成功执行、产出转账结果、不触碰策略', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const to = actors(1)[0]!.address;
  const data = Buffer.from('calldata');
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 5000n, to, value: 777n, data,
  });
  const task = wallet.submitTransaction(
    { nonce: 0n, deadline: 5000n, to, value: 777n, data },
    sigs,
  );
  const done = wallet.executeNext();
  assert.equal(done!.id, task.id);
  assert.equal(done!.status, 'executed');
  assert.deepEqual(done!.receipt!.result, {
    kind: 'transfer',
    to,
    value: 777n,
    data: data.toString('hex'),
  });
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
});

test('混合队列：普通交易与策略变更按 FIFO 交错执行，行为各自独立', () => {
  const { wallet, ownerActors } = setup(3, 2n);
  const newbie = actors(1)[0]!;

  // nonce 0：普通交易
  const to = newbie.address;
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9000n, to, value: 10n, data: new Uint8Array(),
  });
  const tTx = wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 10n }, txSigs);

  // nonce 1：策略变更（降阈值到 1）
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const tPc = propose(wallet, ownerActors, { nonce: 1n, deadline: 9000n, newOwners: ownersA, newConfirmations: 1n });

  assert.deepEqual(wallet.tasks.map((t) => t.seq), [0, 1]);

  const r1 = wallet.executeNext();
  assert.equal(r1!.id, tTx.id);
  assert.equal(r1!.status, 'executed');
  assert.equal(wallet.policyVersion, 1n);

  const r2 = wallet.executeNext();
  assert.equal(r2!.id, tPc.id);
  assert.equal(r2!.status, 'executed');
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.requiredConfirmations, 1n);

  // 新策略：nonce 2 普通交易只需 1 个当前所有者签名
  const to2 = ownerActors[2]!.address; // 已不是所有者
  void to2;
  const tx2Sigs = signTransaction([newbie], {
    walletId: WALLET, nonce: 2n, deadline: 9500n, to: ownerActors[0]!.address, value: 1n, data: new Uint8Array(),
  });
  const tTx2 = wallet.submitTransaction(
    { nonce: 2n, deadline: 9500n, to: ownerActors[0]!.address, value: 1n },
    tx2Sigs,
  );
  assert.equal(wallet.executeTask(tTx2.id).status, 'executed');
});
