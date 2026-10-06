import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, type ValueThreshold } from '../src/wallet.ts';
import {
  ApprovalRevocationThresholdNotMetError,
  ApprovalThresholdNotMetError,
  InvalidCancellation,
  InvalidPolicyChange,
  InvalidSpendingPolicy,
  InvalidSpendingValueError,
  InvalidTransaction,
  InvalidTransactionBatch,
} from '../src/errors.ts';
import { hashTransaction } from '../src/encoding.ts';
import {
  actors,
  addresses,
  fakeClock,
  signApprovalRevocation,
  signBatchApproval,
  signBatchTransaction,
  signCancellation,
  signPolicyApproval,
  signPolicyChange,
  signTransaction,
  signTransactionApproval,
  type Actor,
} from './helpers.ts';
import { generateKeyPair } from '../src/crypto.ts';

const WALLET = 'wallet-tiers';
const TO = generateKeyPair().address;

const TIERS: ValueThreshold[] = [
  { minimumValue: 100n, confirmations: 3n },
  { minimumValue: 1000n, confirmations: 4n },
];

/** 默认：4 个所有者、全局确认数 2、两级静态阈值（100→3，1000→4） */
function setup(opts: { thresholds?: ValueThreshold[]; owners?: number; confirmations?: bigint } = {}) {
  const ownerActors = actors(opts.owners ?? 4);
  const clock = fakeClock(1000n);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations: opts.confirmations ?? 2n,
    valueThresholds: opts.thresholds ?? TIERS,
    now: clock.now,
  });
  return { ownerActors, clock, wallet };
}

function txSigs(signers: Actor[], nonce: bigint, value: bigint, to: string = TO) {
  return signTransaction(signers, { walletId: WALLET, nonce, deadline: 9000n, to, value });
}

// ---------- 构造时策略校验 ----------

test('构造：合法分级阈值生效；缺省与空数组行为一致', () => {
  const { wallet } = setup();
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.equal(wallet.requiredConfirmationsForValue(0n), 2n);

  const ownerActors = actors(3);
  for (const valueThresholds of [undefined, []] as const) {
    const w = new MultiSigWallet({
      id: WALLET,
      owners: addresses(ownerActors),
      confirmations: 2n,
      ...(valueThresholds === undefined ? {} : { valueThresholds }),
    });
    assert.equal(w.requiredConfirmationsForValue(10n ** 30n), 2n);
  }
});

test('构造：minimumValue 非正 / 达到 2^256 / 未严格递增 → InvalidSpendingPolicy', () => {
  const ownerActors = actors(4);
  const base = { id: WALLET, owners: addresses(ownerActors), confirmations: 2n };
  const bad: ValueThreshold[][] = [
    [{ minimumValue: 0n, confirmations: 3n }],
    [{ minimumValue: -1n, confirmations: 3n }],
    [{ minimumValue: 2n ** 256n, confirmations: 3n }],
    [{ minimumValue: 100n, confirmations: 3n }, { minimumValue: 100n, confirmations: 4n }],
    [{ minimumValue: 1000n, confirmations: 3n }, { minimumValue: 100n, confirmations: 4n }],
  ];
  for (const valueThresholds of bad) {
    assert.throws(() => new MultiSigWallet({ ...base, valueThresholds }), InvalidSpendingPolicy);
  }
});

test('构造：confirmations 非正 / 低于全局 / 高于所有者数 / 随金额下降 → InvalidSpendingPolicy', () => {
  const ownerActors = actors(4);
  const base = { id: WALLET, owners: addresses(ownerActors), confirmations: 2n };
  const bad: ValueThreshold[][] = [
    [{ minimumValue: 100n, confirmations: 0n }],
    [{ minimumValue: 100n, confirmations: 1n }], // 低于全局确认数 2
    [{ minimumValue: 100n, confirmations: 5n }], // 高于所有者数 4
    [
      { minimumValue: 100n, confirmations: 4n },
      { minimumValue: 1000n, confirmations: 3n }, // 随金额下降
    ],
  ];
  for (const valueThresholds of bad) {
    assert.throws(() => new MultiSigWallet({ ...base, valueThresholds }), InvalidSpendingPolicy);
  }
  // 非数组、非对象项、非法标量同样拒绝
  for (const valueThresholds of [
    42 as any,
    'x' as any,
    [null] as any,
    [{}] as any,
    [{ minimumValue: 1.5, confirmations: 3n }] as any,
    [{ minimumValue: 100n, confirmations: Number.MAX_SAFE_INTEGER + 1 }] as any,
  ]) {
    assert.throws(() => new MultiSigWallet({ ...base, valueThresholds }), InvalidSpendingPolicy);
  }
});

// ---------- 纯查询 ----------

test('requiredConfirmationsForValue：取不超过 value 的最高档，未命中返回全局确认数', () => {
  const { wallet } = setup();
  assert.equal(wallet.requiredConfirmationsForValue(0n), 2n);
  assert.equal(wallet.requiredConfirmationsForValue(99n), 2n);
  assert.equal(wallet.requiredConfirmationsForValue(100n), 3n);
  assert.equal(wallet.requiredConfirmationsForValue(999n), 3n);
  assert.equal(wallet.requiredConfirmationsForValue(1000n), 4n);
  assert.equal(wallet.requiredConfirmationsForValue(2n ** 256n - 1n), 4n);
});

test('requiredConfirmationsForValue：负数或超 256 位金额 → InvalidSpendingValueError', () => {
  const { wallet } = setup();
  assert.throws(() => wallet.requiredConfirmationsForValue(-1n), InvalidSpendingValueError);
  assert.throws(() => wallet.requiredConfirmationsForValue(2n ** 256n), InvalidSpendingValueError);
  assert.throws(() => wallet.requiredConfirmationsForValue('x' as any), InvalidSpendingValueError);
});

test('requiredConfirmationsForBatch：按 value 总额取档；空批量或非法调用项 → InvalidTransactionBatch', () => {
  const { wallet } = setup();
  const call = (value: bigint) => ({ to: TO, value, data: new Uint8Array() });
  assert.equal(wallet.requiredConfirmationsForBatch([call(10n)]), 2n);
  assert.equal(wallet.requiredConfirmationsForBatch([call(60n), call(60n)]), 3n); // 总额 120
  assert.equal(wallet.requiredConfirmationsForBatch([call(600n), call(500n)]), 4n); // 总额 1100
  assert.throws(() => wallet.requiredConfirmationsForBatch([]), InvalidTransactionBatch);
  assert.throws(
    () => wallet.requiredConfirmationsForBatch([{ to: TO, value: -1n, data: new Uint8Array() }]),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.requiredConfirmationsForBatch([{ to: TO, value: 1n, data: 'x' } as any]),
    InvalidTransactionBatch,
  );
});

test('查询不消费 nonce、不建任务、不改状态', () => {
  const { wallet } = setup();
  wallet.requiredConfirmationsForValue(1000n);
  wallet.requiredConfirmationsForBatch([{ to: TO, value: 500n, data: new Uint8Array() }]);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  assert.deepEqual(wallet.policy, { owners: wallet.currentOwners, confirmations: 2n, version: 1n });
});

// ---------- 直接提交：单笔按金额、批量按总额、策略变更按最大档 ----------

test('直接提交：高金额交易阈值不足 → InvalidTransaction；补足后成功且只产对应任务', () => {
  const { wallet, ownerActors } = setup();
  // 阈值档 100 → 需 3 签；只有 2 签（满足全局确认数）被拒
  assert.throws(
    () => wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to: TO, value: 100n }, txSigs(ownerActors.slice(0, 2), 0n, 100n)),
    InvalidTransaction,
  );
  // 失败不消费 nonce、不建任务
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);

  const task = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: TO, value: 100n },
    txSigs(ownerActors.slice(0, 3), 0n, 100n),
  );
  assert.equal(task.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
  // 摘要与既有 safe-wallet/tx/v1 域一致（阈值不进签名载荷）
  assert.equal(
    task.digest,
    hashTransaction({ walletId: WALLET, nonce: 0n, deadline: 9000n, to: TO, value: 100n, data: new Uint8Array() }).toString('hex'),
  );
  // 低于档位的金额仍按全局确认数
  const low = wallet.submitTransaction(
    { nonce: 1n, deadline: 9000n, to: TO, value: 99n },
    txSigs(ownerActors.slice(0, 2), 1n, 99n),
  );
  assert.equal(low.status, 'queued');
});

test('直接提交：批量按 value 总额取档，阈值不足 → InvalidTransactionBatch', () => {
  const { wallet, ownerActors } = setup();
  const calls = [
    { to: TO, value: 60n, data: new Uint8Array() },
    { to: TO, value: 60n, data: new Uint8Array([1]) },
  ]; // 总额 120 → 需 3 签
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, signBatchTransaction(ownerActors.slice(0, 2), { walletId: WALLET, nonce: 0n, deadline: 9000n, calls })),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.expectedNonce, 0n);
  const task = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: 9000n, calls },
    signBatchTransaction(ownerActors.slice(0, 3), { walletId: WALLET, nonce: 0n, deadline: 9000n, calls }),
  );
  assert.equal(task.status, 'queued');
  const receipt = wallet.executeTask(task.id);
  assert.equal((receipt.receipt!.result as { kind: string }).kind, 'transfer-batch');
});

test('直接提交：策略变更使用最大档确认数；新所有者数低于最大档 → InvalidPolicyChange', () => {
  const { wallet, ownerActors } = setup();
  const newOwners = addresses(ownerActors); // 4 个所有者，不变
  const pc = { version: 1n, nonce: 0n, deadline: 9000n, newOwners, newConfirmations: 2n };
  // 最大档为 4：2 签、3 签都不足
  for (const n of [2, 3]) {
    assert.throws(
      () => wallet.proposePolicyChange(pc, signPolicyChange(ownerActors.slice(0, n), { walletId: WALLET, ...pc })),
      InvalidPolicyChange,
    );
  }
  assert.equal(wallet.expectedNonce, 0n);
  const task = wallet.proposePolicyChange(pc, signPolicyChange(ownerActors, { walletId: WALLET, ...pc }));
  assert.equal(task.status, 'queued');

  // 新所有者数低于最大档确认数（3 < 4）→ InvalidPolicyChange
  const { wallet: w2, ownerActors: oa2 } = setup();
  const shrink = {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(oa2).slice(0, 3),
    newConfirmations: 2n,
  };
  assert.throws(
    () => w2.proposePolicyChange(shrink, signPolicyChange(oa2, { walletId: WALLET, ...shrink })),
    InvalidPolicyChange,
  );
});

// ---------- 分阶段审批：创建时绑定有效阈值 ----------

test('交易审批：创建时按金额绑定阈值；签名不足 → ApprovalThresholdNotMetError，补足后提交', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 100n });
  assert.equal(approval.confirmations, 3n);
  assert.equal(approval.status, 'collecting');

  for (const signer of ownerActors.slice(0, 2)) {
    const [sig] = signTransactionApproval([signer], { walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n, to: TO, value: 100n });
    wallet.addApprovalSignature(approval.id, sig!);
  }
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'collecting');
  assert.throws(() => wallet.submitApprovedTransaction(approval.id), ApprovalThresholdNotMetError);
  // 失败不消费 nonce、不建任务
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);

  const [third] = signTransactionApproval([ownerActors[2]!], { walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n, to: TO, value: 100n });
  wallet.addApprovalSignature(approval.id, third!);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');
  const task = wallet.submitApprovedTransaction(approval.id);
  assert.equal(task.status, 'queued');
  // 与直接提交同一摘要、同一载荷形状
  assert.equal(
    task.digest,
    hashTransaction({ walletId: WALLET, nonce: 0n, deadline: 9000n, to: TO, value: 100n, data: new Uint8Array() }).toString('hex'),
  );

  // 低金额审批仍按全局确认数
  const low = wallet.createTransactionApproval({ nonce: 1n, deadline: 9000n, to: TO, value: 5n });
  assert.equal(low.confirmations, 2n);
});

test('批量审批：按 value 总额绑定阈值；策略审批：绑定最大档', () => {
  const { wallet, ownerActors } = setup();
  const calls = [
    { to: TO, value: 60n, data: new Uint8Array() },
    { to: TO, value: 60n, data: new Uint8Array() },
  ];
  const batch = wallet.createBatchApproval({ nonce: 0n, deadline: 9000n, calls });
  assert.equal(batch.confirmations, 3n);
  for (const signer of ownerActors.slice(0, 2)) {
    const [sig] = signBatchApproval([signer], { walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n, calls });
    wallet.addBatchApprovalSignature(batch.id, sig!);
  }
  assert.throws(() => wallet.submitBatchApproval(batch.id), ApprovalThresholdNotMetError);
  const [third] = signBatchApproval([ownerActors[2]!], { walletId: WALLET, version: 1n, nonce: 0n, deadline: 9000n, calls });
  wallet.addBatchApprovalSignature(batch.id, third!);
  const task = wallet.submitBatchApproval(batch.id);
  assert.equal(task.payload.kind, 'transaction-batch');

  const policy = wallet.createPolicyApproval({
    version: 1n,
    nonce: 1n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  assert.equal(policy.confirmations, 4n);
  for (const signer of ownerActors.slice(0, 3)) {
    const [sig] = signPolicyApproval([signer], {
      walletId: WALLET,
      version: 1n,
      nonce: 1n,
      deadline: 9000n,
      newOwners: addresses(ownerActors),
      newConfirmations: 2n,
    });
    wallet.addPolicyApprovalSignature(policy.id, sig!);
  }
  assert.throws(() => wallet.submitApprovedPolicyChange(policy.id), ApprovalThresholdNotMetError);
  const [fourth] = signPolicyApproval([ownerActors[3]!], {
    walletId: WALLET,
    version: 1n,
    nonce: 1n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  wallet.addPolicyApprovalSignature(policy.id, fourth!);
  assert.equal(wallet.submitApprovedPolicyChange(policy.id).payload.kind, 'policy-change');
});

// ---------- 取消与撤销：按目标的有效阈值 ----------

test('取消：单笔 / 批量任务按对应有效阈值，策略任务按最大档；不足 → InvalidCancellation', () => {
  const { wallet, ownerActors } = setup();
  // 高金额交易任务（需 3 签）
  const txTask = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: TO, value: 100n },
    txSigs(ownerActors.slice(0, 3), 0n, 100n),
  );
  assert.throws(
    () =>
      wallet.cancelTask(
        { taskId: txTask.id, nonce: 1n, deadline: 9000n },
        signCancellation(ownerActors.slice(0, 2), { walletId: WALLET, taskDigest: txTask.digest, nonce: 1n, deadline: 9000n }),
      ),
    InvalidCancellation,
  );
  const cancelled = wallet.cancelTask(
    { taskId: txTask.id, nonce: 1n, deadline: 9000n },
    signCancellation(ownerActors.slice(0, 3), { walletId: WALLET, taskDigest: txTask.digest, nonce: 1n, deadline: 9000n }),
  );
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(wallet.expectedNonce, 2n);

  // 策略任务取消需最大档 4 签
  const pc = { version: 1n, nonce: 2n, deadline: 9000n, newOwners: addresses(ownerActors), newConfirmations: 2n };
  const pcTask = wallet.proposePolicyChange(pc, signPolicyChange(ownerActors, { walletId: WALLET, ...pc }));
  assert.throws(
    () =>
      wallet.cancelTask(
        { taskId: pcTask.id, nonce: 3n, deadline: 9000n },
        signCancellation(ownerActors.slice(0, 3), { walletId: WALLET, taskDigest: pcTask.digest, nonce: 3n, deadline: 9000n }),
      ),
    InvalidCancellation,
  );
  const cancelledPc = wallet.cancelTask(
    { taskId: pcTask.id, nonce: 3n, deadline: 9000n },
    signCancellation(ownerActors, { walletId: WALLET, taskDigest: pcTask.digest, nonce: 3n, deadline: 9000n }),
  );
  assert.equal(cancelledPc.status, 'cancelled');
});

test('撤销：按目标审批的有效阈值；不足 → ApprovalRevocationThresholdNotMetError', () => {
  const { wallet, ownerActors } = setup();
  // 高金额交易审批（有效阈值 3）
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 100n });
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: 9000n },
        signApprovalRevocation(ownerActors.slice(0, 2), { walletId: WALLET, approvalDigest: approval.digest, nonce: 0n, deadline: 9000n }),
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  // 失败不消费 nonce、审批状态不变
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'collecting');

  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    signApprovalRevocation(ownerActors.slice(0, 3), { walletId: WALLET, approvalDigest: approval.digest, nonce: 0n, deadline: 9000n }),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.expectedNonce, 1n);

  // 策略审批撤销需最大档 4 签
  const policy = wallet.createPolicyApproval({
    version: 1n,
    nonce: 1n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: policy.id, nonce: 1n, deadline: 9000n },
        signApprovalRevocation(ownerActors.slice(0, 3), { walletId: WALLET, approvalDigest: policy.digest, nonce: 1n, deadline: 9000n }),
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  const revokedPolicy = wallet.revokeApproval(
    { approvalId: policy.id, nonce: 1n, deadline: 9000n },
    signApprovalRevocation(ownerActors, { walletId: WALLET, approvalDigest: policy.digest, nonce: 1n, deadline: 9000n }),
  );
  assert.equal(revokedPolicy.status, 'revoked');
});

// ---------- 无规则钱包：行为与既有完全一致 ----------

test('无分级规则钱包：任意金额 / 策略操作仍按全局确认数', () => {
  const ownerActors = actors(3);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations: 2n,
    now: fakeClock(1000n).now,
  });
  assert.equal(wallet.requiredConfirmationsForValue(10n ** 30n), 2n);
  // 巨额交易仍只需 2 签
  const task = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: TO, value: 10n ** 30n },
    txSigs(ownerActors.slice(0, 2), 0n, 10n ** 30n),
  );
  assert.equal(task.status, 'queued');
  // 策略变更也仍只需 2 签，且新所有者数不受最大档限制
  const pc = { version: 1n, nonce: 1n, deadline: 9000n, newOwners: [ownerActors[0]!.address], newConfirmations: 1n };
  const pcTask = wallet.proposePolicyChange(pc, signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...pc }));
  assert.equal(pcTask.status, 'queued');
});
