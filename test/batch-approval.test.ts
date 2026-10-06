import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, MAX_BATCH_CALLS, type BatchCallSubmission } from '../src/wallet.ts';
import {
  ApprovalAlreadySubmittedError,
  ApprovalExpiredError,
  ApprovalNotFoundError,
  ApprovalPolicyConflictError,
  ApprovalThresholdNotMetError,
  DuplicateApprovalSignatureError,
  InvalidApprovalSignatureError,
  InvalidTransactionBatch,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { hashTransactionBatch, hashTransactionBatchApproval } from '../src/encoding.ts';
import { generateKeyPair } from '../src/crypto.ts';
import {
  actors,
  addresses,
  fakeClock,
  signBatchApproval,
  signBatchTransaction,
  signCancellation,
  signPolicyChange,
  signTransaction,
  type Actor,
} from './helpers.ts';

const WALLET = 'wallet-batch-approval';

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

const outsider = generateKeyPair();

type CallSpec = { to: string; value: bigint; data: Uint8Array };

function makeCalls(n: number): CallSpec[] {
  return Array.from({ length: n }, (_, i) => ({
    to: generateKeyPair().address,
    value: BigInt(i + 1),
    data: Buffer.from(`call-${i}`),
  }));
}

type BatchInput = { nonce: bigint; deadline: bigint; calls: readonly BatchCallSubmission[] };

function batchInput(calls: readonly BatchCallSubmission[], overrides: Partial<BatchInput> = {}): BatchInput {
  return { nonce: 0n, deadline: 9000n, calls, ...overrides };
}

function approvalSigs(ownerActors: Actor[], input: BatchInput, count = 2, version = 1n) {
  return signBatchApproval(ownerActors.slice(0, count), {
    walletId: WALLET,
    version,
    nonce: input.nonce,
    deadline: input.deadline,
    calls: input.calls.map((c) => ({ to: c.to, value: BigInt(c.value), data: c.data })),
  });
}

/** 创建 + 收集满阈值签名，返回审批快照 */
function readyApproval(wallet: MultiSigWallet, ownerActors: Actor[], input: BatchInput) {
  const a = wallet.createBatchApproval(input);
  for (const sig of approvalSigs(ownerActors, input)) {
    wallet.addBatchApprovalSignature(a.id, sig);
  }
  return wallet.getBatchApproval(a.id);
}

/** 通过直接策略变更让版本漂移（审批不消费 nonce，故用 nonce 0；版本 1 → 2） */
function driftPolicy(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const input = {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  };
  const sigs = signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  const task = wallet.proposePolicyChange(input, sigs);
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
}

// ---------- 创建 ----------

test('创建批量审批：返回完整快照（摘要/calls/签名者/状态），不消费 nonce、不建任务、不改策略', () => {
  const { wallet, ownerActors } = setup();
  const before = {
    nonce: wallet.expectedNonce,
    version: wallet.policyVersion,
    owners: wallet.currentOwners,
    confirmations: wallet.requiredConfirmations,
  };
  const calls = makeCalls(3);
  const input = batchInput(calls);

  const a = wallet.createBatchApproval(input);
  assert.equal(typeof a.id, 'string');
  assert.ok(a.id.length > 0);
  assert.equal(a.version, 1n);
  assert.equal(a.confirmations, 2n);
  assert.equal(a.nonce, 0n);
  assert.equal(a.deadline, 9000n);
  assert.deepEqual(
    a.calls.map((c) => ({ to: c.to, value: c.value, data: Buffer.from(c.data) })),
    calls.map((c) => ({ to: c.to, value: c.value, data: Buffer.from(c.data) })),
  );
  assert.deepEqual(a.signers, []);
  assert.equal(a.status, 'collecting');

  // 摘要与 safe-wallet/tx-batch-approval/v1 域一致
  const expected = hashTransactionBatchApproval({ walletId: WALLET, version: 1n, ...input });
  assert.equal(a.digest, expected.toString('hex'));
  // 与直接提交的 safe-wallet/tx-batch/v1 摘要不同（两域签名互不通用）
  const directDigest = hashTransactionBatch({ walletId: WALLET, nonce: 0n, deadline: 9000n, calls });
  assert.notEqual(a.digest, directDigest.toString('hex'));

  // 登记不产生任何既有状态变化
  assert.equal(wallet.expectedNonce, before.nonce);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, before.version);
  assert.deepEqual(wallet.currentOwners, before.owners);
  assert.equal(wallet.requiredConfirmations, before.confirmations);
});

test('创建批量审批：calls 顺序参与摘要绑定，顺序不同摘要不同', () => {
  const { wallet } = setup();
  const calls = makeCalls(2);
  const a = wallet.createBatchApproval(batchInput(calls));
  const b = wallet.createBatchApproval(batchInput([calls[1]!, calls[0]!]));
  assert.notEqual(a.digest, b.digest);
});

test('创建批量审批：任一调用字段变化即改摘要（收款地址 / 金额 / data / 项数）', () => {
  const { wallet } = setup();
  const calls = makeCalls(2);
  const base = wallet.createBatchApproval(batchInput(calls));
  const otherTo = wallet.createBatchApproval(
    batchInput([{ ...calls[0]!, to: generateKeyPair().address }, calls[1]!]),
  );
  const otherValue = wallet.createBatchApproval(
    batchInput([{ ...calls[0]!, value: calls[0]!.value + 1n }, calls[1]!]),
  );
  const otherData = wallet.createBatchApproval(
    batchInput([{ ...calls[0]!, data: Buffer.from('tampered') }, calls[1]!]),
  );
  const fewer = wallet.createBatchApproval(batchInput([calls[0]!]));
  for (const other of [otherTo, otherValue, otherData, fewer]) {
    assert.notEqual(base.digest, other.digest);
  }
});

test('创建批量审批：同一 nonce 可登记多个候选（创建不消费 nonce）', () => {
  const { wallet } = setup();
  const a = wallet.createBatchApproval(batchInput(makeCalls(1)));
  const b = wallet.createBatchApproval(batchInput(makeCalls(2)));
  assert.notEqual(a.id, b.id);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.deepEqual(
    wallet.listBatchApprovals().map((x) => x.id),
    [a.id, b.id],
  );
});

test('创建批量审批：nonce 复用抛 NonceAlreadyUsedError（优先于过期判定）', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(1);
  const sigs = signBatchTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    calls,
  });
  wallet.submitBatchTransaction({ nonce: 0n, deadline: 9000n, calls }, sigs);
  assert.throws(() => wallet.createBatchApproval(batchInput(makeCalls(1))), NonceAlreadyUsedError);
  // 已过期也仍报复用
  assert.throws(
    () => wallet.createBatchApproval(batchInput(makeCalls(1), { deadline: 500n })),
    NonceAlreadyUsedError,
  );
});

test('创建批量审批：过期 deadline 抛 RequestExpired，nonce 跳号抛 InvalidTransactionBatch', () => {
  const { wallet } = setup();
  assert.throws(
    () => wallet.createBatchApproval(batchInput(makeCalls(1), { deadline: 999n })),
    RequestExpired,
  );
  assert.throws(
    () => wallet.createBatchApproval(batchInput(makeCalls(1), { nonce: 1n })),
    InvalidTransactionBatch,
  );
  // 失败不留审批
  assert.equal(wallet.listBatchApprovals().length, 0);
});

test('创建批量审批：沿用 1..64 项与逐项字段校验，非法登记抛 InvalidTransactionBatch', () => {
  const { wallet } = setup();
  // 空列表 / 超上限
  assert.throws(() => wallet.createBatchApproval(batchInput([])), InvalidTransactionBatch);
  assert.throws(
    () => wallet.createBatchApproval(batchInput(makeCalls(MAX_BATCH_CALLS + 1))),
    InvalidTransactionBatch,
  );
  // 64 项合法
  const ok = wallet.createBatchApproval(batchInput(makeCalls(MAX_BATCH_CALLS)));
  assert.equal(ok.calls.length, MAX_BATCH_CALLS);
  // 零地址收款方
  assert.throws(
    () =>
      wallet.createBatchApproval(
        batchInput([{ to: '0x0000000000000000000000000000000000000000', value: 1n, data: new Uint8Array() }]),
      ),
    InvalidTransactionBatch,
  );
  // 非法地址 / 金额越界 / data 非 Uint8Array
  assert.throws(
    () => wallet.createBatchApproval(batchInput([{ to: 'not-an-address', value: 1n, data: new Uint8Array() }])),
    InvalidTransactionBatch,
  );
  assert.throws(
    () =>
      wallet.createBatchApproval(
        batchInput([{ to: generateKeyPair().address, value: -1n, data: new Uint8Array() }]),
      ),
    InvalidTransactionBatch,
  );
  assert.throws(
    () =>
      wallet.createBatchApproval(
        batchInput([{ to: generateKeyPair().address, value: 1n, data: '0x12' as unknown as Uint8Array }]),
      ),
    InvalidTransactionBatch,
  );
  // 全部失败不留任何审批 / nonce / 任务变化
  assert.equal(wallet.listBatchApprovals().length, 1);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建批量审批：创建后改动入参 data 不影响审批内容与摘要（内部持有副本）', () => {
  const { wallet } = setup();
  const data = Buffer.from('original');
  const a = wallet.createBatchApproval(
    batchInput([{ to: generateKeyPair().address, value: 1n, data }]),
  );
  data[0] = 0xff;
  const again = wallet.getBatchApproval(a.id);
  assert.equal(Buffer.from(again.calls[0]!.data).toString(), 'original');
  assert.equal(again.digest, a.digest);
});

// ---------- 加签 ----------

test('加签：逐个收集当前所有者签名，按加签顺序记录，达阈值后状态 ready', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  const sigs = approvalSigs(ownerActors, input);

  const after1 = wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.deepEqual(after1.signers, [ownerActors[0]!.address]);
  assert.equal(after1.status, 'collecting');

  const after2 = wallet.addBatchApprovalSignature(a.id, sigs[1]!);
  assert.deepEqual(after2.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);
  assert.equal(after2.status, 'ready');

  // 加签不改 nonce / 队列 / 策略
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, 1n);
});

test('加签：未知 id 抛 ApprovalNotFoundError', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const sigs = approvalSigs(ownerActors, input, 1);
  assert.throws(() => wallet.addBatchApprovalSignature('nope', sigs[0]!), ApprovalNotFoundError);
  assert.throws(() => wallet.getBatchApproval('nope'), ApprovalNotFoundError);
  assert.throws(() => wallet.submitBatchApproval('nope'), ApprovalNotFoundError);
});

test('加签：非法签名抛 InvalidApprovalSignatureError（长度 / 非所有者 / 与摘要不符）', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  const sigs = approvalSigs(ownerActors, input);

  // 非 65 字节
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, new Uint8Array(64)), InvalidApprovalSignatureError);
  // 非所有者签名
  const foreign = signBatchApproval([outsider], {
    walletId: WALLET,
    version: 1n,
    nonce: input.nonce,
    deadline: input.deadline,
    calls: input.calls.map((c) => ({ to: c.to, value: BigInt(c.value), data: c.data })),
  });
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, foreign[0]!), InvalidApprovalSignatureError);
  // 与摘要不符：用另一批 calls 的审批签名
  const other = approvalSigs(ownerActors, batchInput(makeCalls(3)), 1);
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, other[0]!), InvalidApprovalSignatureError);
  // 直接提交域（safe-wallet/tx-batch/v1）的签名不能用于审批
  const direct = signBatchTransaction(ownerActors.slice(0, 1), {
    walletId: WALLET,
    nonce: input.nonce,
    deadline: input.deadline,
    calls: input.calls.map((c) => ({ to: c.to, value: BigInt(c.value), data: c.data })),
  });
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, direct[0]!), InvalidApprovalSignatureError);

  // 全部失败不改变审批内容
  assert.deepEqual(wallet.getBatchApproval(a.id).signers, []);
  assert.equal(wallet.getBatchApproval(a.id).status, 'collecting');
  // 合法签名仍可加入
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.deepEqual(wallet.getBatchApproval(a.id).signers, [ownerActors[0]!.address]);
});

test('加签：同一所有者重复加签抛 DuplicateApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  const sigs = approvalSigs(ownerActors, input);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[0]!), DuplicateApprovalSignatureError);
  assert.deepEqual(wallet.getBatchApproval(a.id).signers, [ownerActors[0]!.address]);
});

// ---------- 查询与列表 ----------

test('查询与列表：返回摘要、calls、签名者、状态；列表按创建顺序', () => {
  const { wallet, ownerActors } = setup();
  const input1 = batchInput(makeCalls(1));
  const input2 = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input1);
  const b = wallet.createBatchApproval(input2);
  wallet.addBatchApprovalSignature(a.id, approvalSigs(ownerActors, input1, 1)[0]!);

  const got = wallet.getBatchApproval(a.id);
  assert.equal(got.digest, a.digest);
  assert.equal(got.calls.length, 1);
  assert.deepEqual(got.signers, [ownerActors[0]!.address]);
  assert.equal(got.status, 'collecting');

  const list = wallet.listBatchApprovals();
  assert.deepEqual(
    list.map((x) => x.id),
    [a.id, b.id],
  );
  assert.equal(list[1]!.calls.length, 2);
  assert.deepEqual(list[1]!.signers, []);
});

// ---------- 过期与版本漂移 ----------

test('批量审批过期：加签 / 提交抛 ApprovalExpiredError，查询状态 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = batchInput(makeCalls(1), { deadline: 2000n });
  const a = wallet.createBatchApproval(input);
  const sigs = approvalSigs(ownerActors, input);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  clock.set(2001n);

  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[1]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalExpiredError);
  assert.equal(wallet.getBatchApproval(a.id).status, 'expired');
  // 失败不变
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('批量审批版本漂移：加签 / 提交抛 ApprovalPolicyConflictError，查询状态 conflicted', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  const sigs = approvalSigs(ownerActors, input);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);

  driftPolicy(wallet, ownerActors);

  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[1]!), ApprovalPolicyConflictError);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalPolicyConflictError);
  assert.equal(wallet.getBatchApproval(a.id).status, 'conflicted');
});

test('批量审批过期优先于版本冲突：同时发生时抛 ApprovalExpiredError，查询 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = batchInput(makeCalls(1), { deadline: 2000n });
  const a = wallet.createBatchApproval(input);
  driftPolicy(wallet, ownerActors);
  clock.set(3000n);

  const sigs = approvalSigs(ownerActors, input, 1);
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[0]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalExpiredError);
  assert.equal(wallet.getBatchApproval(a.id).status, 'expired');
});

// ---------- 提交 ----------

test('提交批量审批：按 tx-batch/v1 摘要只入队一个 transaction-batch 任务，只消费创建时 nonce', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(3);
  const input = batchInput(calls);
  const a = readyApproval(wallet, ownerActors, input);
  assert.equal(a.status, 'ready');

  const task = wallet.submitBatchApproval(a.id);
  assert.equal(task.payload.kind, 'transaction-batch');
  assert.equal(task.nonce, 0n);
  // 任务摘要与既有直接提交域一致
  const expected = hashTransactionBatch({ walletId: WALLET, nonce: 0n, deadline: 9000n, calls });
  assert.equal(task.digest, expected.toString('hex'));
  if (task.payload.kind !== 'transaction-batch') throw new Error('wrong payload kind');
  assert.equal(task.payload.calls.length, 3);

  // 只入队一个任务、只消费一个 nonce
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.getBatchApproval(a.id).status, 'submitted');
});

test('提交批量审批：签名不足阈值抛 ApprovalThresholdNotMetError，不留任何变化', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  wallet.addBatchApprovalSignature(a.id, approvalSigs(ownerActors, input, 1)[0]!);

  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.getBatchApproval(a.id).status, 'collecting');
});

test('提交批量审批：已提交后重复提交 / 加签抛 ApprovalAlreadySubmittedError', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = readyApproval(wallet, ownerActors, input);
  wallet.submitBatchApproval(a.id);

  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalAlreadySubmittedError);
  const sigs = approvalSigs(ownerActors, input, 3);
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[2]!), ApprovalAlreadySubmittedError);
  assert.equal(wallet.tasks.length, 1);
});

test('提交批量审批：nonce 已被其他路径消费抛 NonceAlreadyUsedError，同 nonce 候选只入队一个', () => {
  const { wallet, ownerActors } = setup();
  // 同一 nonce 登记两个候选
  const a = readyApproval(wallet, ownerActors, batchInput(makeCalls(1)));
  const b = readyApproval(wallet, ownerActors, batchInput(makeCalls(2)));

  wallet.submitBatchApproval(a.id);
  assert.throws(() => wallet.submitBatchApproval(b.id), NonceAlreadyUsedError);
  // 只有一个批量任务入队
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.tasks[0]!.payload.kind, 'transaction-batch');
  assert.equal(wallet.expectedNonce, 1n);

  // 直接提交消费 nonce 后，绑定该 nonce 的审批同样无法提交
  const { wallet: w2, ownerActors: oa2 } = setup();
  const c = readyApproval(w2, oa2, batchInput(makeCalls(1)));
  const to = generateKeyPair().address;
  const txSigs = signTransaction(oa2.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to,
  });
  w2.submitTransaction({ nonce: 0n, deadline: 9000n, to, value: 0n }, txSigs);
  assert.throws(() => w2.submitBatchApproval(c.id), NonceAlreadyUsedError);
  assert.equal(w2.tasks.length, 1);
});

test('提交后执行：整批一个 transfer-batch 回执，FIFO 与幂等语义不变', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(3);
  const a = readyApproval(wallet, ownerActors, batchInput(calls));
  const task = wallet.submitBatchApproval(a.id);

  const done = wallet.executeNext()!;
  assert.equal(done.id, task.id);
  assert.equal(done.status, 'executed');
  const result = done.receipt!.result as {
    kind: string;
    calls: { to: string; value: bigint; data: string }[];
  };
  assert.equal(result.kind, 'transfer-batch');
  assert.deepEqual(
    result.calls,
    calls.map((c) => ({ to: c.to, value: c.value, data: Buffer.from(c.data).toString('hex') })),
  );
  // 重复执行幂等
  const again = wallet.executeTask(task.id);
  assert.equal(again, done);
  assert.equal(again.receipt, done.receipt);
  // 策略未被触碰
  assert.equal(wallet.policyVersion, 1n);
});

test('提交后任务可取消：取消语义与直接提交的批量任务一致', () => {
  const { wallet, ownerActors } = setup();
  const a = readyApproval(wallet, ownerActors, batchInput(makeCalls(2)));
  const task = wallet.submitBatchApproval(a.id);

  const sigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: task.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  const cancelled = wallet.cancelTask(task.id, 1n, 9000n, sigs);
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(wallet.expectedNonce, 2n);
});
