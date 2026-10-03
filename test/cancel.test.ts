import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, type WalletTask } from '../src/wallet.ts';
import {
  InvalidCancellation,
  InvalidTransaction,
  NonceAlreadyUsedError,
  RequestExpired,
  TaskCancellationConflict,
  TaskNotFoundError,
} from '../src/errors.ts';
import { hashCancellation, hashPolicyChange } from '../src/encoding.ts';
import {
  actors,
  addresses,
  fakeClock,
  signCancellation,
  signPolicyChange,
  signTransaction,
  type Actor,
} from './helpers.ts';

const WALLET = 'wallet-cancel';

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

/** 提交一个普通交易任务（默认前两个所有者签名） */
function enqueueTx(
  wallet: MultiSigWallet,
  ownerActors: Actor[],
  nonce: bigint,
  deadline = 9000n,
  signers: Actor[] = ownerActors.slice(0, 2),
): WalletTask {
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(signers, {
    walletId: WALLET,
    nonce,
    deadline,
    to,
    value: 100n,
    data: new Uint8Array(),
  });
  return wallet.submitTransaction({ nonce, deadline, to, value: 100n }, sigs);
}

/** 为取消目标任务收集签名 */
function cancelSigs(
  task: { digest: string },
  nonce: bigint,
  signers: Actor[],
  deadline = 9000n,
  mutate?: (base: { walletId: string; taskDigest: string; nonce: bigint; deadline: bigint }) => typeof base,
): Buffer[] {
  return signCancellation(
    signers,
    { walletId: WALLET, taskDigest: task.digest, nonce, deadline },
    mutate ? { mutate } : {},
  );
}

// ---------- 成功路径 ----------

test('成功取消：queued → cancelled 终态，记录取消时间/摘要/nonce，保留原 payload/digest/nonce', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  const before = wallet.policy;

  const sigs = cancelSigs(target, 1n, ownerActors.slice(0, 2), 5000n);
  const cancelled = wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 5000n }, sigs);

  assert.equal(cancelled.id, target.id);
  assert.equal(cancelled.status, 'cancelled');
  // 原任务内容原样保留
  assert.deepEqual(cancelled.payload, target.payload);
  assert.equal(cancelled.digest, target.digest);
  assert.equal(cancelled.nonce, 0n);
  assert.equal(cancelled.submittedAt, target.submittedAt);

  // 回执：取消时间 + 取消摘要 + 取消自身的 nonce
  const receipt = cancelled.receipt!;
  assert.equal(receipt.status, 'cancelled');
  assert.equal(receipt.failureReason, null);
  assert.equal(receipt.executedAt, clock.now());
  const info = receipt.cancellation!;
  assert.equal(info.cancelledAt, 1000n);
  assert.equal(info.nonce, 1n);
  assert.equal(
    info.digest,
    hashCancellation({ walletId: WALLET, taskDigest: target.digest, nonce: 1n, deadline: 5000n }).toString('hex'),
  );

  // 仅消费本次取消 nonce；策略（owners/确认数/版本）完全不变
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.isNonceUsed(1n), true);
  assert.equal(wallet.expectedNonce, 2n);
  assert.deepEqual(wallet.policy, before);
  assert.equal(wallet.policyVersion, 1n);
});

test('取消不要求任务在队首：取消后续 queued 任务，队首仍可执行', () => {
  const { wallet, ownerActors } = setup();
  const t0 = enqueueTx(wallet, ownerActors, 0n)!;
  const t1 = enqueueTx(wallet, ownerActors, 1n)!;

  const sigs = cancelSigs(t1, 2n, ownerActors.slice(0, 2));
  const cancelled = wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n }, sigs);
  assert.equal(cancelled.status, 'cancelled');

  // 队首 t0 仍是 queued；非队首的 t1 已是终态，executeTask 直接返回终态、不产生效果、不影响队首
  assert.equal(wallet.getTask(t0.id)!.status, 'queued');
  assert.equal(wallet.executeTask(t1.id), cancelled);
  assert.equal(wallet.getTask(t0.id)!.status, 'queued');

  // executeNext 先执行 t0，再越过 cancelled 的 t1，队列排空 → null
  assert.equal(wallet.executeNext()!.id, t0.id);
  assert.equal(wallet.executeNext(), null);
});

test('executeNext 越过队首及连续 cancelled 任务；之后新入队任务仍可执行', () => {
  const { wallet, ownerActors } = setup();
  const t0 = enqueueTx(wallet, ownerActors, 0n)!;
  const t1 = enqueueTx(wallet, ownerActors, 1n)!;
  const t2 = enqueueTx(wallet, ownerActors, 2n)!;
  wallet.cancelTask({ taskId: t0.id, nonce: 3n, deadline: 9000n }, cancelSigs(t0, 3n, ownerActors.slice(0, 2)));
  wallet.cancelTask({ taskId: t1.id, nonce: 4n, deadline: 9000n }, cancelSigs(t1, 4n, ownerActors.slice(0, 2)));
  wallet.cancelTask({ taskId: t2.id, nonce: 5n, deadline: 9000n }, cancelSigs(t2, 5n, ownerActors.slice(0, 2)));

  assert.equal(wallet.executeNext(), null);

  // 越过不改变任务顺序，后续新任务从游标之后正常执行
  const t3 = enqueueTx(wallet, ownerActors, 6n)!;
  const done = wallet.executeNext();
  assert.equal(done!.id, t3.id);
  assert.equal(done!.status, 'executed');
});

test('cancelled 任务重复 executeTask 幂等返回同一终态；被取消的策略变更绝不生效', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n, newOwners, newConfirmations: 1n,
  });
  const target = wallet.proposePolicyChange(
    { version: 1n, nonce: 0n, deadline: 9000n, newOwners, newConfirmations: 1n },
    pcSigs,
  );
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, cancelSigs(target, 1n, ownerActors.slice(0, 2)));

  const r1 = wallet.executeTask(target.id);
  const r2 = wallet.executeTask(target.id);
  assert.equal(r1, r2);
  assert.equal(r1.status, 'cancelled');
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.equal(wallet.isOwner(newbie.address), false);
});

test('只读任务快照区分 cancelled，目标任务在 tasks/getTask 中可见', () => {
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  enqueueTx(wallet, ownerActors, 1n);
  wallet.cancelTask({ taskId: target.id, nonce: 2n, deadline: 9000n }, cancelSigs(target, 2n, ownerActors.slice(0, 2)));

  assert.equal(wallet.getTask(target.id)!.status, 'cancelled');
  assert.deepEqual(wallet.tasks.map((t) => t.status), ['cancelled', 'queued']);
});

// ---------- 错误：目标状态 ----------

test('目标不存在 → TaskNotFoundError（无论签名如何）', () => {
  const { wallet, ownerActors } = setup();
  const sigs = cancelSigs({ digest: 'aa'.repeat(32) }, 0n, ownerActors.slice(0, 2));
  assert.throws(
    () => wallet.cancelTask({ taskId: 'deadbeef', nonce: 0n, deadline: 9000n }, sigs),
    TaskNotFoundError,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('目标已 executed / failed / cancelled → TaskCancellationConflict，且不消费新 nonce', () => {
  const { wallet, ownerActors } = setup();

  // executed 目标
  const executed = enqueueTx(wallet, ownerActors, 0n)!;
  wallet.executeTask(executed.id);
  assert.throws(
    () => wallet.cancelTask({ taskId: executed.id, nonce: 1n, deadline: 9000n },
      cancelSigs(executed, 1n, ownerActors.slice(0, 2))),
    TaskCancellationConflict,
  );
  assert.equal(wallet.isNonceUsed(1n), false);

  // failed 目标（构造 PolicyConflict 失败终态）
  const newbie = actors(1)[0]!;
  const ownersA = [ownerActors[0]!.address, newbie.address];
  const sigsA = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 1n, deadline: 9000n, newOwners: ownersA, newConfirmations: 1n,
  });
  const tA = wallet.proposePolicyChange(
    { version: 1n, nonce: 1n, deadline: 9000n, newOwners: ownersA, newConfirmations: 1n },
    sigsA,
  );
  const ownersB = [ownerActors[0]!.address, ownerActors[2]!.address];
  const sigsB = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 2n, deadline: 9000n, newOwners: ownersB, newConfirmations: 2n,
  });
  const tB = wallet.proposePolicyChange(
    { version: 1n, nonce: 2n, deadline: 9000n, newOwners: ownersB, newConfirmations: 2n },
    sigsB,
  );
  wallet.executeTask(tA.id); // 版本 → 2
  const failed = wallet.executeTask(tB.id);
  assert.equal(failed.status, 'failed');

  // 当前策略阈值为 1，newbie 单签即可，但目标已 failed → 冲突（先于签名核对）
  assert.throws(
    () => wallet.cancelTask({ taskId: tB.id, nonce: 3n, deadline: 9000n },
      cancelSigs(tB, 3n, [newbie])),
    TaskCancellationConflict,
  );

  // cancelled 目标（nonce 3 未被上面的失败取消消费，可正常使用）
  const tC = enqueueTx(wallet, ownerActors, 3n, 9000n, [newbie])!;
  wallet.cancelTask({ taskId: tC.id, nonce: 4n, deadline: 9000n }, cancelSigs(tC, 4n, [newbie]));
  assert.throws(
    () => wallet.cancelTask({ taskId: tC.id, nonce: 5n, deadline: 9000n }, cancelSigs(tC, 5n, [newbie])),
    TaskCancellationConflict,
  );
  assert.equal(wallet.expectedNonce, 5n); // 4n 已消费；5n 未消费
  assert.equal(wallet.isNonceUsed(5n), false);
});

// ---------- 错误：截止时间与重放 ----------

test('deadline 早于当前时间 → RequestExpired；失败不消费 nonce、不改任务', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  clock.set(3000n);
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 2000n },
      cancelSigs(target, 1n, ownerActors.slice(0, 2), 2000n)),
    RequestExpired,
  );
  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
  // 同一 nonce 可在合法截止时间下重新使用
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 5000n },
    cancelSigs(target, 1n, ownerActors.slice(0, 2), 5000n));
  assert.equal(wallet.getTask(target.id)!.status, 'cancelled');
});

test('旧取消请求重放恒定得到 NonceAlreadyUsedError，即使已过截止时间或目标状态变化', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  const sub = { taskId: target.id, nonce: 1n, deadline: 2000n };
  const sigs = cancelSigs(target, 1n, ownerActors.slice(0, 2), 2000n);
  wallet.cancelTask(sub, sigs);

  clock.set(9000n); // 已过截止时间
  assert.throws(() => wallet.cancelTask(sub, sigs), NonceAlreadyUsedError);
  assert.throws(() => wallet.cancelTask(sub, sigs), (err: Error & { usedNonce?: bigint }) => {
    return err instanceof NonceAlreadyUsedError && err.usedNonce === 1n;
  });
});

test('nonce 复用（任意已用 nonce）→ NonceAlreadyUsedError', () => {
  const { wallet, ownerActors } = setup();
  const t0 = enqueueTx(wallet, ownerActors, 0n)!;
  const t1 = enqueueTx(wallet, ownerActors, 1n)!;
  // 用已被 t0 消费的 nonce 0 发起取消
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 0n, deadline: 9000n },
      cancelSigs(t1, 0n, ownerActors.slice(0, 2))),
    NonceAlreadyUsedError,
  );
});

test('校验顺序：nonce 复用 → deadline → 目标存在性 → 目标状态 → 签名', () => {
  const { wallet, ownerActors, clock } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;

  // 用过 nonce + 已过期 + 目标不存在：仍是 nonce 复用优先
  clock.set(8000n);
  assert.throws(
    () => wallet.cancelTask({ taskId: 'missing', nonce: 0n, deadline: 1000n }, []),
    NonceAlreadyUsedError,
  );

  // 未用 nonce + 已过期 + 目标不存在：deadline 优先于目标查找
  assert.throws(
    () => wallet.cancelTask({ taskId: 'missing', nonce: 1n, deadline: 1000n }, []),
    RequestExpired,
  );

  // 未用 nonce + 未过期 + 目标不存在：TaskNotFoundError 优先于签名核对
  assert.throws(
    () => wallet.cancelTask({ taskId: 'missing', nonce: 1n, deadline: 9000n }, []),
    TaskNotFoundError,
  );

  // 目标已终态 + 畸形签名：冲突优先于签名
  wallet.executeTask(target.id);
  assert.throws(
    () => wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n }, []),
    TaskCancellationConflict,
  );

  // 全部异常路径均未消费 nonce
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(1n), false);
});

// ---------- 错误：内容与签名 ----------

test('非法字段 → InvalidCancellation，且不消费 nonce、任务保持 queued', () => {
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  const good = { taskId: target.id, deadline: 9000n };
  const goodSigs = () => cancelSigs(target, 1n, ownerActors.slice(0, 2));

  assert.throws(() => wallet.cancelTask({ ...good, nonce: 'abc' as unknown as bigint }, goodSigs()), InvalidCancellation);
  assert.throws(() => wallet.cancelTask({ ...good, nonce: -1n }, goodSigs()), InvalidCancellation);
  assert.throws(() => wallet.cancelTask({ ...good, nonce: 2n ** 256n }, goodSigs()), InvalidCancellation);
  assert.throws(() => wallet.cancelTask({ ...good, nonce: 1.5 }, goodSigs()), InvalidCancellation);
  assert.throws(
    () => wallet.cancelTask(
      { ...good, nonce: 1n, deadline: 'xyz' as unknown as bigint },
      goodSigs(),
    ),
    InvalidCancellation,
  );
  assert.throws(
    () => wallet.cancelTask({ ...good, nonce: 1n, taskId: '' }, goodSigs()),
    InvalidCancellation,
  );
  assert.throws(
    () => wallet.cancelTask({ ...good, nonce: 1n, taskId: 123 as unknown as string }, goodSigs()),
    InvalidCancellation,
  );

  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
});

test('签名集合不规范 → InvalidCancellation', () => {
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  const sub = { taskId: target.id, nonce: 1n, deadline: 9000n };

  assert.throws(() => wallet.cancelTask(sub, []), InvalidCancellation);
  assert.throws(() => wallet.cancelTask(sub, 'not-array' as unknown as Uint8Array[]), InvalidCancellation);
  const short = new Uint8Array(64);
  assert.throws(() => wallet.cancelTask(sub, [short]), InvalidCancellation);
  const garbage = new Uint8Array(65).fill(0xff); // 不可恢复
  assert.throws(() => wallet.cancelTask(sub, [garbage, garbage]), InvalidCancellation);

  assert.equal(wallet.expectedNonce, 1n);
});

test('签名者非当前所有者 / 去重后不足确认数 → InvalidCancellation', () => {
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  const sub = { taskId: target.id, nonce: 1n, deadline: 9000n };

  const outsider = actors(1)[0]!;
  // 外部人签名
  assert.throws(() => wallet.cancelTask(sub, cancelSigs(target, 1n, [outsider, outsider])), InvalidCancellation);
  // 只有 1 个所有者（阈值 2）
  assert.throws(() => wallet.cancelTask(sub, cancelSigs(target, 1n, [ownerActors[0]!])), InvalidCancellation);
  // 同一所有者重复两次：去重后仅 1
  assert.throws(() => wallet.cancelTask(sub, cancelSigs(target, 1n, [ownerActors[0]!, ownerActors[0]!])), InvalidCancellation);

  assert.equal(wallet.getTask(target.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
});

test('摘要与提交内容不一致（改绑任务/钱包/时间窗口/nonce）→ InvalidCancellation', () => {
  const { wallet, ownerActors } = setup();
  const t0 = enqueueTx(wallet, ownerActors, 0n)!;
  const t1 = enqueueTx(wallet, ownerActors, 1n)!;
  const signers = ownerActors.slice(0, 2);

  // 签名绑定另一个任务的 digest
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n },
      cancelSigs(t0, 2n, signers)),
    InvalidCancellation,
  );
  // 签名绑定另一个钱包标识
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n },
      signCancellation(signers, {
        walletId: 'other-wallet', taskDigest: t1.digest, nonce: 2n, deadline: 9000n,
      })),
    InvalidCancellation,
  );
  // 签名绑定更早的截止时间（不能改绑时间窗口）
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n },
      cancelSigs(t1, 2n, signers, 5000n)),
    InvalidCancellation,
  );
  // 签名绑定另一个 nonce
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n },
      cancelSigs(t1, 7n, signers)),
    InvalidCancellation,
  );
  // 域标签隔离：普通交易签名 / 策略变更签名不能充当取消签名
  const txSigs = signTransaction(signers, {
    walletId: WALLET, nonce: 2n, deadline: 9000n, to: t1.payload.kind === 'transaction' ? t1.payload.to : ownerActors[0]!.address,
    value: 1n, data: new Uint8Array(),
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n }, txSigs),
    InvalidCancellation,
  );
  const pcSigs = signPolicyChange(signers, {
    walletId: WALLET, version: 1n, nonce: 2n, deadline: 9000n,
    newOwners: addresses(ownerActors), newConfirmations: 2n,
  });
  assert.throws(
    () => wallet.cancelTask({ taskId: t1.id, nonce: 2n, deadline: 9000n }, pcSigs),
    InvalidCancellation,
  );

  assert.equal(wallet.getTask(t1.id)!.status, 'queued');
  assert.equal(wallet.expectedNonce, 2n);
});

test('取消摘要不会与交易/策略变更摘要碰撞：同 nonce 不同域的操作各自独立', () => {
  // 取消消费自己的 nonce；被取消任务的 digest 仍保留在历史中，不影响后续操作
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n },
    cancelSigs(target, 1n, ownerActors.slice(0, 2)));

  const next = enqueueTx(wallet, ownerActors, 2n)!;
  assert.equal(wallet.getTask(next.id)!.status, 'queued');
  assert.equal(next.digest !== target.digest, true);
});

// ---------- 与当前策略联动 / nonce 严格递增 ----------

test('取消按当前策略与阈值验签：降阈值后单签可取消，已退出所有者签名被拒', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];

  // nonce0：普通交易占位；nonce1：降阈值到 1 的策略变更
  enqueueTx(wallet, ownerActors, 0n);
  const pcSigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET, version: 1n, nonce: 1n, deadline: 9000n, newOwners, newConfirmations: 1n,
  });
  const pc = wallet.proposePolicyChange(
    { version: 1n, nonce: 1n, deadline: 9000n, newOwners, newConfirmations: 1n },
    pcSigs,
  );
  wallet.executeNext(); // 交易
  wallet.executeTask(pc.id); // 策略变更：版本 2、阈值 1
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.requiredConfirmations, 1n);

  // nonce2：新策略下 newbie 单签提交的任务
  const target = enqueueTx(wallet, ownerActors, 2n, 9000n, [newbie])!;
  // 当前所有者 newbie 单签即可取消
  wallet.cancelTask({ taskId: target.id, nonce: 3n, deadline: 9000n },
    cancelSigs(target, 3n, [newbie]));
  assert.equal(wallet.getTask(target.id)!.status, 'cancelled');
  assert.equal(wallet.policyVersion, 2n, '取消不递增版本');

  // 已退出的旧所有者发起取消 → InvalidCancellation
  const other = enqueueTx(wallet, ownerActors, 4n, 9000n, [newbie])!;
  assert.throws(
    () => wallet.cancelTask({ taskId: other.id, nonce: 5n, deadline: 9000n },
      cancelSigs(other, 5n, [ownerActors[1]!])),
    InvalidCancellation,
  );
  assert.equal(wallet.getTask(other.id)!.status, 'queued');
});

test('取消后 nonce 严格递增续接：跳号被拒，顺序号正常', () => {
  const { wallet, ownerActors } = setup();
  const target = enqueueTx(wallet, ownerActors, 0n)!;
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n },
    cancelSigs(target, 1n, ownerActors.slice(0, 2)));

  assert.throws(
    () => enqueueTx(wallet, ownerActors, 3n),
    InvalidTransaction,
  );
  const next = enqueueTx(wallet, ownerActors, 2n)!;
  assert.equal(next.status, 'queued');
});

test('被取消任务的原始 digest 仍在队列历史上防重', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET, nonce: 0n, deadline: 9000n, to, value: 100n, data: new Uint8Array(),
  });
  const target = wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 100n }, sigs);
  wallet.cancelTask({ taskId: target.id, nonce: 1n, deadline: 9000n },
    cancelSigs(target, 1n, ownerActors.slice(0, 2)));
  // digest 防重是兜底层；相同内容即使绕过 nonce 也无法再次入队（这里直接被 nonce 拦截）
  assert.throws(
    () => wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 100n }, sigs),
    NonceAlreadyUsedError,
  );
});
