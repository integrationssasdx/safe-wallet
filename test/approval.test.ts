import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import {
  ApprovalAlreadySubmittedError,
  ApprovalExpiredError,
  ApprovalNotFoundError,
  ApprovalPolicyConflictError,
  ApprovalThresholdNotMetError,
  DuplicateApprovalSignatureError,
  InvalidApprovalSignatureError,
  InvalidTransaction,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { hashTransaction, hashTransactionApproval } from '../src/encoding.ts';
import { generateKeyPair } from '../src/crypto.ts';
import {
  actors,
  addresses,
  fakeClock,
  signPolicyChange,
  signTransaction,
  signTransactionApproval,
  type Actor,
} from './helpers.ts';

const WALLET = 'wallet-approval';

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

const TO = generateKeyPair().address;

function createApproval(wallet: MultiSigWallet, nonce = 0n, deadline = 9000n, value = 7n) {
  return wallet.createTransactionApproval({ nonce, deadline, to: TO, value });
}

function approvalSigs(ownerActors: Actor[], count: number, nonce = 0n, deadline = 9000n, version = 1n, value = 7n) {
  return signTransactionApproval(ownerActors.slice(0, count), {
    walletId: WALLET,
    version,
    nonce,
    deadline,
    to: TO,
    value,
  });
}

// ---------- 创建 ----------

test('创建审批：返回标识/摘要/版本/确认数/空签名者，状态 collecting，不消费 nonce、不建任务', () => {
  const { wallet } = setup();
  const before = wallet.expectedNonce;

  const a = createApproval(wallet);
  assert.equal(typeof a.id, 'string');
  assert.ok(a.id.length > 0);
  assert.equal(a.version, 1n);
  assert.equal(a.confirmations, 2n);
  assert.deepEqual(a.signers, []);
  assert.equal(a.status, 'collecting');

  // 摘要与 safe-wallet/tx-approval/v1 域一致，且与直接提交摘要不同
  const expected = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  assert.equal(a.digest, expected.toString('hex'));
  const txDigest = hashTransaction({ walletId: WALLET, nonce: 0n, deadline: 9000n, to: TO, value: 7n, data: new Uint8Array() });
  assert.notEqual(a.digest, txDigest.toString('hex'));

  // 不消费 nonce、不建任务
  assert.equal(wallet.expectedNonce, before);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
});

test('创建审批：同一 nonce 可登记多笔审批（创建不消费 nonce），标识各不相同', () => {
  const { wallet } = setup();
  const a = createApproval(wallet);
  const b = createApproval(wallet);
  assert.notEqual(a.id, b.id);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建审批：字段非法或跳号抛 InvalidTransaction', () => {
  const { wallet } = setup();
  assert.throws(
    () => wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: '0x1234', value: 1n }),
    InvalidTransaction,
  );
  assert.throws(
    () => wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: -1n }),
    InvalidTransaction,
  );
  assert.throws(
    () => wallet.createTransactionApproval({ nonce: 5n, deadline: 9000n, to: TO, value: 1n }),
    InvalidTransaction,
  );
  // 失败不产生状态
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建审批：nonce 已用抛 NonceAlreadyUsedError（优先于过期），过期抛 RequestExpired', () => {
  const { wallet, ownerActors } = setup();
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 1n,
  });
  wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to: TO, value: 1n }, sigs);

  // 已用 nonce + 已过期 deadline：仍报复用
  assert.throws(
    () => wallet.createTransactionApproval({ nonce: 0n, deadline: 500n, to: TO, value: 1n }),
    NonceAlreadyUsedError,
  );
  assert.throws(
    () => wallet.createTransactionApproval({ nonce: 1n, deadline: 500n, to: TO, value: 1n }),
    RequestExpired,
  );
});

// ---------- 加签 ----------

test('加签：逐个收集当前所有者签名，达到阈值后状态 ready，签名者按加签顺序', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);

  const mid = wallet.addApprovalSignature(a.id, sigs[0]!);
  assert.equal(mid.status, 'collecting');
  assert.deepEqual(mid.signers, [ownerActors[0]!.address]);

  const ready = wallet.addApprovalSignature(a.id, sigs[1]!);
  assert.equal(ready.status, 'ready');
  assert.deepEqual(ready.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);

  const queried = wallet.getTransactionApproval(a.id);
  assert.equal(queried.status, 'ready');
  assert.deepEqual(queried.signers, ready.signers);
});

test('加签：同一所有者重复签名抛 DuplicateApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);
  wallet.addApprovalSignature(a.id, sigs[0]!);
  assert.throws(() => wallet.addApprovalSignature(a.id, sigs[0]!), DuplicateApprovalSignatureError);
});

test('加签：格式非法、摘要不符或签名者非所有者抛 InvalidApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);

  // 非 65 字节
  assert.throws(() => wallet.addApprovalSignature(a.id, new Uint8Array(64)), InvalidApprovalSignatureError);
  // 非所有者签名（用外部密钥对同一摘要签名）
  const outsider = actors(1);
  const outsiderSig = signTransactionApproval(outsider, {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  assert.throws(() => wallet.addApprovalSignature(a.id, outsiderSig[0]!), InvalidApprovalSignatureError);
  // 摘要不符：直接提交域（safe-wallet/tx/v1）的签名不能用于审批
  const txSig = signTransaction(ownerActors.slice(0, 1), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  assert.throws(() => wallet.addApprovalSignature(a.id, txSig[0]!), InvalidApprovalSignatureError);
  // 全部失败后可继续正常加签
  wallet.addApprovalSignature(a.id, sigs[0]!);
  assert.equal(wallet.getTransactionApproval(a.id).signers.length, 1);
});

test('未知审批 id：加签 / 查询 / 提交均抛 ApprovalNotFoundError', () => {
  const { wallet, ownerActors } = setup();
  const sigs = approvalSigs(ownerActors, 1);
  assert.throws(() => wallet.addApprovalSignature('nope', sigs[0]!), ApprovalNotFoundError);
  assert.throws(() => wallet.getTransactionApproval('nope'), ApprovalNotFoundError);
  assert.throws(() => wallet.submitApprovedTransaction('nope'), ApprovalNotFoundError);
});

// ---------- 过期与版本漂移 ----------

test('过期：加签 / 提交抛 ApprovalExpiredError，查询状态 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const a = createApproval(wallet, 0n, 2000n);
  const sigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 2000n,
    to: TO,
    value: 7n,
  });
  wallet.addApprovalSignature(a.id, sigs[0]!);
  clock.set(2001n);

  assert.throws(() => wallet.addApprovalSignature(a.id, sigs[1]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalExpiredError);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'expired');
});

/** 通过策略变更让版本漂移（审批不消费 nonce，故策略变更用 nonce 0；版本 1 → 2） */
function driftPolicy(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  const task = wallet.proposePolicyChange(
    { version: 1n, nonce: 0n, deadline: 9000n, newOwners: addresses(ownerActors), newConfirmations: 2n },
    sigs,
  );
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
}

test('版本漂移：加签 / 提交抛 ApprovalPolicyConflictError，查询状态 conflicted', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);
  wallet.addApprovalSignature(a.id, sigs[0]!);

  driftPolicy(wallet, ownerActors);

  assert.throws(() => wallet.addApprovalSignature(a.id, sigs[1]!), ApprovalPolicyConflictError);
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalPolicyConflictError);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'conflicted');
});

test('过期优先于版本冲突：同时发生时抛 ApprovalExpiredError，查询 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const a = createApproval(wallet, 0n, 2000n);
  driftPolicy(wallet, ownerActors);
  clock.set(3000n);

  const sigs = approvalSigs(ownerActors, 1, 0n, 2000n);
  assert.throws(() => wallet.addApprovalSignature(a.id, sigs[0]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalExpiredError);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'expired');
});

// ---------- 提交 ----------

test('提交：阈值满足后按 tx/v1 摘要入队，只消费创建时 nonce，返回普通交易任务', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);
  wallet.addApprovalSignature(a.id, sigs[0]!);
  wallet.addApprovalSignature(a.id, sigs[1]!);

  const task = wallet.submitApprovedTransaction(a.id);
  assert.equal(task.status, 'queued');
  assert.equal(task.nonce, 0n);
  assert.equal(task.payload.kind, 'transaction');
  // 任务摘要是既有 safe-wallet/tx/v1 域
  const txDigest = hashTransaction({
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  assert.equal(task.digest, txDigest.toString('hex'));

  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'submitted');

  // 任务可正常执行，回执与直接提交一致
  const executed = wallet.executeTask(task.id);
  assert.equal(executed.status, 'executed');
  assert.deepEqual(executed.receipt?.result, { kind: 'transfer', to: TO, value: 7n, data: '' });
});

test('提交后：加签 / 重复提交抛 ApprovalAlreadySubmittedError，查询 submitted', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 3);
  for (const s of sigs.slice(0, 2)) wallet.addApprovalSignature(a.id, s);
  wallet.submitApprovedTransaction(a.id);

  assert.throws(() => wallet.addApprovalSignature(a.id, sigs[2]!), ApprovalAlreadySubmittedError);
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalAlreadySubmittedError);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'submitted');
});

test('提交：签名不足抛 ApprovalThresholdNotMetError，不消费 nonce、不建任务', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  wallet.addApprovalSignature(a.id, approvalSigs(ownerActors, 1)[0]!);

  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'collecting');
});

test('提交：创建后 nonce 被其他提交消费 → NonceAlreadyUsedError，审批不消费、不建任务', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const sigs = approvalSigs(ownerActors, 2);
  for (const s of sigs) wallet.addApprovalSignature(a.id, s);

  // 直接提交消费 nonce 0
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 1n,
  });
  wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to: TO, value: 1n }, txSigs);

  assert.throws(() => wallet.submitApprovedTransaction(a.id), NonceAlreadyUsedError);
  // 审批仍未提交，任务数不增
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'ready');
});

test('分阶段审批与既有 FIFO 队列共存：审批任务按入队顺序执行', () => {
  const { wallet, ownerActors } = setup();
  // 直接提交 nonce 0
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 1n,
  });
  wallet.submitTransaction({ nonce: 0n, deadline: 9000n, to: TO, value: 1n }, txSigs);

  // 审批绑定 nonce 1，分阶段收集后提交
  const a = wallet.createTransactionApproval({ nonce: 1n, deadline: 9000n, to: TO, value: 2n });
  const sigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 1n,
    deadline: 9000n,
    to: TO,
    value: 2n,
  });
  for (const s of sigs) wallet.addApprovalSignature(a.id, s);
  const task = wallet.submitApprovedTransaction(a.id);
  assert.equal(task.nonce, 1n);
  assert.equal(wallet.expectedNonce, 2n);

  const first = wallet.executeNext();
  assert.equal(first?.nonce, 0n);
  const second = wallet.executeNext();
  assert.equal(second?.id, task.id);
  assert.equal(second?.status, 'executed');
});
