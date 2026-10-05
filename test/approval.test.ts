import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, type TransactionApproval } from '../src/wallet.ts';
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
import {
  actors,
  addresses,
  fakeClock,
  signPolicyChange,
  signTransaction,
  signTransactionApproval,
  type Actor,
} from './helpers.ts';
import { generateKeyPair } from '../src/crypto.ts';

const WALLET = 'wallet-approval';
const RECIPIENT = generateKeyPair().address;

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

const approvalSub = (over: Record<string, unknown> = {}) => ({
  nonce: 0n,
  deadline: 5000n,
  to: RECIPIENT,
  value: 100n,
  ...over,
});

/** 创建审批并返回审批视图（默认 3 所有者 / 阈值 2） */
function createApproval(wallet: MultiSigWallet, over: Record<string, unknown> = {}) {
  return wallet.createTransactionApproval(approvalSub(over));
}

/** 单个所有者对审批加签 */
function signOne(ownerActors: Actor[], index: number, approval: TransactionApproval) {
  const [sig] = signTransactionApproval(
    [ownerActors[index]!],
    {
      walletId: WALLET,
      version: approval.version,
      nonce: approval.nonce,
      deadline: approval.deadline,
      to: approval.to,
      value: approval.value,
      data: approval.data,
    },
  );
  return sig!;
}

/** 提交并执行一次策略变更（nonce 0，阈值签名），推进策略版本并消费 nonce */
function applyPolicyChange(
  wallet: MultiSigWallet,
  ownerActors: Actor[],
  clock: ReturnType<typeof fakeClock>,
  newConfirmations = 2n,
) {
  const nonce = wallet.expectedNonce;
  const params = {
    walletId: WALLET,
    version: wallet.policyVersion,
    nonce,
    deadline: clock.now() + 10000n,
    newOwners: addresses(ownerActors),
    newConfirmations,
  };
  const sigs = signPolicyChange(ownerActors.slice(0, 2), params);
  const task = wallet.proposePolicyChange(
    {
      version: params.version,
      nonce: params.nonce,
      deadline: params.deadline,
      newOwners: params.newOwners,
      newConfirmations: params.newConfirmations,
    },
    sigs,
  );
  return wallet.executeTask(task.id);
}

// ---------- 创建 ----------

test('创建审批：collecting，返回标识/摘要/版本/确认数/签名者；不消费 nonce、不入队', () => {
  const { wallet } = setup();
  const a = createApproval(wallet);
  assert.equal(a.status, 'collecting');
  assert.equal(typeof a.id, 'string');
  assert.equal(a.id.length, 16);
  assert.equal(a.version, 1n);
  assert.equal(a.confirmations, 2n);
  assert.equal(a.nonce, 0n);
  assert.deepEqual(a.signers, []);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
});

test('审批摘要走 tx-approval/v1 域：与 tx/v1 摘要不同但字段绑定一致', () => {
  const { wallet } = setup();
  const a = createApproval(wallet);
  const approvalDigest = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
    data: new Uint8Array(),
  }).toString('hex');
  const txDigest = hashTransaction({
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
    data: new Uint8Array(),
  }).toString('hex');
  assert.equal(a.digest, approvalDigest);
  assert.notEqual(a.digest, txDigest);
});

test('创建审批：data 被复制，调用方事后改动缓冲区不影响审批摘要', () => {
  const { wallet, ownerActors } = setup();
  const data = Buffer.from('original');
  const a = createApproval(wallet, { data });
  data.fill(0xff);
  // 用“原始内容”的签名仍能加签成功，说明记录内部保留的是副本
  const sig = signOne(ownerActors, 0, { ...a, data: Buffer.from('original') });
  const updated = wallet.addApprovalSignature(a.id, sig);
  assert.deepEqual(updated.signers, [ownerActors[0]!.address]);
});

test('重复创建同一审批（同摘要）幂等返回同一条记录', () => {
  const { wallet } = setup();
  const a1 = createApproval(wallet);
  const a2 = createApproval(wallet);
  assert.equal(a2.id, a1.id);
  assert.deepEqual(a2.signers, []);
});

test('创建审批：字段非法 / 跳号 → InvalidTransaction；失败不消费 nonce', () => {
  const { wallet } = setup();
  assert.throws(() => createApproval(wallet, { nonce: 1n }), InvalidTransaction);
  assert.throws(() => createApproval(wallet, { to: '0x' + '00'.repeat(20) }), InvalidTransaction);
  assert.throws(() => createApproval(wallet, { to: 'not-an-address' }), InvalidTransaction);
  assert.throws(() => createApproval(wallet, { value: -1n }), InvalidTransaction);
  assert.throws(() => createApproval(wallet, { data: 'nope' }), InvalidTransaction);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建审批：nonce 已用 → NonceAlreadyUsedError；过期 → RequestExpired', () => {
  const { wallet, ownerActors } = setup();
  // 先用既有入口消费 nonce 0
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
  });
  wallet.submitTransaction(approvalSub(), sigs);
  assert.throws(() => createApproval(wallet), NonceAlreadyUsedError);

  // 过期判定（新 nonce）
  assert.throws(() => createApproval(wallet, { nonce: 1n, deadline: 500n }), RequestExpired);
});

// ---------- 加签 ----------

test('加签：collecting → 达阈值 ready；签名者按加签顺序返回，超过阈值仍可加签', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);

  const after1 = wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  assert.equal(after1.status, 'collecting');
  assert.deepEqual(after1.signers, [ownerActors[0]!.address]);

  const after2 = wallet.addApprovalSignature(a.id, signOne(ownerActors, 2, after1));
  assert.equal(after2.status, 'ready');
  assert.deepEqual(after2.signers, [ownerActors[0]!.address, ownerActors[2]!.address]);

  // 阈值满足后第三个所有者仍可加签，顺序保持
  const after3 = wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, after2));
  assert.equal(after3.status, 'ready');
  assert.deepEqual(after3.signers, [
    ownerActors[0]!.address,
    ownerActors[2]!.address,
    ownerActors[1]!.address,
  ]);
});

test('加签：同一所有者重复签名 → DuplicateApprovalSignatureError，且不污染已收集签名', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  assert.throws(
    () => wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a)),
    DuplicateApprovalSignatureError,
  );
  const view = wallet.getTransactionApproval(a.id);
  assert.equal(view.signers.length, 1);
});

test('加签：签名格式错误 / 摘要不符 / 非所有者 → InvalidApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);

  // 非 65 字节
  assert.throws(
    () => wallet.addApprovalSignature(a.id, new Uint8Array(64)),
    InvalidApprovalSignatureError,
  );

  // 用 safe-wallet/tx/v1 摘要签名（域不同）：恢复地址不可能是所有者
  const [txSig] = signTransaction([ownerActors[0]!], {
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
  });
  assert.throws(() => wallet.addApprovalSignature(a.id, txSig), InvalidApprovalSignatureError);

  // 外部人对审批摘要签名：签名者不是当前所有者
  const outsider = actors(1)[0]!;
  const [foreign] = signTransactionApproval([outsider], {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
  });
  assert.throws(() => wallet.addApprovalSignature(a.id, foreign), InvalidApprovalSignatureError);

  // 全部拒绝：仍 collecting，签名者为空
  assert.equal(wallet.getTransactionApproval(a.id).status, 'collecting');
});

test('域分隔：审批签名不能用于旧的一次性提交入口', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  const approvalSigs = [
    signOne(ownerActors, 0, a),
    signOne(ownerActors, 1, a),
  ];
  // tx-approval/v1 签名提交到 tx/v1 入口 → 恢复签名者不匹配 → InvalidTransaction
  assert.throws(
    () => wallet.submitTransaction(approvalSub(), approvalSigs),
    InvalidTransaction,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
});

// ---------- 查询与终态 ----------

test('未知 id：查询 / 加签 / 提交 → ApprovalNotFoundError', () => {
  const { wallet, ownerActors } = setup();
  assert.throws(() => wallet.getTransactionApproval('nope'), ApprovalNotFoundError);
  assert.throws(
    () => wallet.addApprovalSignature('nope', new Uint8Array(65)),
    ApprovalNotFoundError,
  );
  assert.throws(() => wallet.submitApprovedTransaction('nope'), ApprovalNotFoundError);
  // 防止 ownerActors 未使用告警
  assert.ok(ownerActors.length === 3);
});

test('过期：查询 expired；加签 / 提交 → ApprovalExpiredError；过期优先于版本漂移', () => {
  const { wallet, ownerActors, clock } = setup();
  const a = wallet.createTransactionApproval(approvalSub({ deadline: 2000n }));
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));

  clock.set(2001n);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'expired');
  assert.throws(
    () => wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a)),
    ApprovalExpiredError,
  );
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalExpiredError);

  // 过期本身未消费 nonce、未建任务
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);

  // 再发生版本漂移：过期仍优先
  applyPolicyChange(wallet, ownerActors, clock);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'expired');
  assert.throws(
    () => wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a)),
    ApprovalExpiredError,
  );
});

test('版本漂移：查询 conflicted；加签 / 提交 → ApprovalPolicyConflictError', () => {
  const { wallet, ownerActors, clock } = setup();
  const a = createApproval(wallet, { deadline: 50000n });
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));

  // 审批仍未过期；策略变更执行后版本推进，nonce 也被消费
  applyPolicyChange(wallet, ownerActors, clock);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'conflicted');
  assert.throws(
    () => wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a)),
    ApprovalPolicyConflictError,
  );
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalPolicyConflictError);
});

test('已提交：查询 submitted；再加签 / 再提交 → ApprovalAlreadySubmittedError', () => {
  const { wallet, ownerActors, clock } = setup();
  const a = createApproval(wallet);
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a));
  const task = wallet.submitApprovedTransaction(a.id);
  assert.equal(task.status, 'queued');

  assert.equal(wallet.getTransactionApproval(a.id).status, 'submitted');
  assert.throws(
    () => wallet.addApprovalSignature(a.id, signOne(ownerActors, 2, a)),
    ApprovalAlreadySubmittedError,
  );
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalAlreadySubmittedError);

  // 之后即使过期也保持 submitted
  clock.set(99999n);
  assert.equal(wallet.getTransactionApproval(a.id).status, 'submitted');
});

// ---------- 提交 ----------

test('提交：签名不足 → ApprovalThresholdNotMetError，不入队、不消费 nonce', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  assert.throws(() => wallet.submitApprovedTransaction(a.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('提交成功：按 tx/v1 摘要入队普通交易任务、只消费创建时 nonce，执行行为不变', () => {
  const { wallet, ownerActors } = setup();
  const data = Buffer.from('hello');
  const a = createApproval(wallet, { data });
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a));

  const task = wallet.submitApprovedTransaction(a.id);
  assert.equal(task.seq, 0);
  assert.equal(task.nonce, 0n);
  assert.equal(task.digest, hashTransaction({
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
    data,
  }).toString('hex'));
  assert.deepEqual(task.payload, {
    kind: 'transaction',
    deadline: 5000n,
    to: RECIPIENT,
    value: 100n,
    data: Buffer.from('hello'),
  });
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(0n), true);

  const executed = wallet.executeNext()!;
  assert.equal(executed.status, 'executed');
  assert.deepEqual(executed.receipt?.result, {
    kind: 'transfer',
    to: RECIPIENT,
    value: 100n,
    data: Buffer.from('hello').toString('hex'),
  });
});

test('提交：创建时 nonce 已被其他入口消费 → NonceAlreadyUsedError，审批不入队', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet);
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a));

  // 旧入口用不同内容的交易先消费 nonce 0
  const otherTo = generateKeyPair().address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 6000n,
    to: otherTo,
    value: 7n,
  });
  wallet.submitTransaction(
    { nonce: 0n, deadline: 6000n, to: otherTo, value: 7n },
    sigs,
  );
  assert.throws(() => wallet.submitApprovedTransaction(a.id), NonceAlreadyUsedError);
  // 队列里只有旧入口的那一个任务
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.tasks[0]!.payload.kind, 'transaction');
});

test('阈值为 1：单个所有者加签即 ready 并可提交', () => {
  const { wallet, ownerActors } = setup(2, 1n);
  const a = createApproval(wallet);
  assert.equal(a.confirmations, 1n);
  const ready = wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  assert.equal(ready.status, 'ready');
  const task = wallet.submitApprovedTransaction(a.id);
  assert.equal(task.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n);
});

test('完整流程：审批入队后下一个 nonce 可继续走旧入口，FIFO 与终态不变', () => {
  const { wallet, ownerActors } = setup();
  const a = createApproval(wallet, { value: 100n });
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 0, a));
  wallet.addApprovalSignature(a.id, signOne(ownerActors, 1, a));
  wallet.submitApprovedTransaction(a.id);

  // nonce 1 的后续交易走旧入口
  const to2 = generateKeyPair().address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 1n,
    deadline: 8000n,
    to: to2,
    value: 200n,
  });
  const second = wallet.submitTransaction(
    { nonce: 1n, deadline: 8000n, to: to2, value: 200n },
    sigs,
  );
  assert.equal(second.seq, 1);
  assert.equal(wallet.expectedNonce, 2n);

  const t1 = wallet.executeNext()!;
  const t2 = wallet.executeNext()!;
  assert.equal(t1.status, 'executed');
  assert.equal(t2.status, 'executed');
  assert.equal(t1.payload.kind, 'transaction');
  assert.equal(t2.payload.kind, 'transaction');

  // 终态幂等：重复执行不重复生效
  const again = wallet.executeTask(t1.id);
  assert.equal(again.status, 'executed');
});
