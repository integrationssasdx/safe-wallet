import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, MAX_BATCH_CALLS } from '../src/wallet.ts';
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
import { hashBatchApproval, hashTransactionBatch } from '../src/encoding.ts';
import { generateKeyPair } from '../src/crypto.ts';
import {
  actors,
  addresses,
  fakeClock,
  signBatchApproval,
  signBatchTransaction,
  signCancellation,
  signPolicyChange,
  signTransactionApproval,
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

const newbie = generateKeyPair();

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

interface BatchInput {
  nonce: bigint;
  deadline: bigint;
  calls: CallSpec[];
}

function batchInput(calls: CallSpec[], overrides: Partial<BatchInput> = {}): BatchInput {
  return { nonce: 0n, deadline: 9000n, calls, ...overrides };
}

function batchSigs(ownerActors: Actor[], input: BatchInput, count = 2) {
  return signBatchApproval(ownerActors.slice(0, count), {
    walletId: WALLET,
    version: 1n,
    ...input,
  });
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

test('创建批量审批：返回完整快照，状态 collecting，不消费 nonce、不建任务、不改策略', () => {
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
  assert.equal(a.confirmations, 2n); // 创建时的当前确认数
  assert.equal(a.nonce, 0n);
  assert.equal(a.deadline, 9000n);
  assert.equal(a.calls.length, 3);
  assert.deepEqual(
    a.calls.map((c) => c.to),
    calls.map((c) => c.to),
  );
  assert.deepEqual(
    a.calls.map((c) => c.value),
    calls.map((c) => c.value),
  );
  assert.deepEqual(
    a.calls.map((c) => Buffer.from(c.data).toString('hex')),
    calls.map((c) => Buffer.from(c.data).toString('hex')),
  );
  assert.deepEqual(a.signers, []);
  assert.equal(a.status, 'collecting');

  // 摘要与 safe-wallet/tx-batch-approval/v1 域一致
  const expected = hashBatchApproval({ walletId: WALLET, version: 1n, ...input });
  assert.equal(a.digest, expected.toString('hex'));
  // 与直接提交的 safe-wallet/tx-batch/v1 摘要不同
  const directDigest = hashTransactionBatch({ walletId: WALLET, ...input });
  assert.notEqual(a.digest, directDigest.toString('hex'));

  // 登记不产生任何既有状态变化
  assert.equal(wallet.expectedNonce, before.nonce);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, before.version);
  assert.deepEqual(wallet.currentOwners, before.owners);
  assert.equal(wallet.requiredConfirmations, before.confirmations);
});

test('创建批量审批：calls 顺序与内容参与摘要绑定，任一变化即改摘要', () => {
  const { wallet } = setup();
  const calls = makeCalls(3);
  const a = wallet.createBatchApproval(batchInput(calls));
  // 顺序不同
  const b = wallet.createBatchApproval(batchInput([calls[1]!, calls[0]!, calls[2]!]));
  assert.notEqual(a.digest, b.digest);
  assert.notEqual(a.id, b.id);
  // 金额不同
  const c = wallet.createBatchApproval(
    batchInput([calls[0]!, { ...calls[1]!, value: calls[1]!.value + 1n }, calls[2]!]),
  );
  assert.notEqual(a.digest, c.digest);
  // data 不同
  const d = wallet.createBatchApproval(
    batchInput([calls[0]!, { ...calls[1]!, data: Buffer.from('other') }, calls[2]!]),
  );
  assert.notEqual(a.digest, d.digest);
  // 项数不同
  const e = wallet.createBatchApproval(batchInput(calls.slice(0, 2)));
  assert.notEqual(a.digest, e.digest);
});

test('创建批量审批：同一 nonce 可登记多个候选（创建不消费 nonce），标识各不相同', () => {
  const { wallet } = setup();
  const calls = makeCalls(2);
  const a = wallet.createBatchApproval(batchInput(calls));
  const b = wallet.createBatchApproval(batchInput(makeCalls(2, 500n)));
  const c = wallet.createBatchApproval(batchInput(calls));
  assert.notEqual(a.id, b.id);
  assert.notEqual(b.id, c.id);
  // 内容完全相同的两个候选摘要一致，但 id 仍由创建序号区分
  assert.equal(a.digest, c.digest);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建批量审批：calls 字段非法或 nonce 跳号抛 InvalidTransactionBatch，失败不留审批', () => {
  const { wallet } = setup();
  const calls = makeCalls(2);
  const base = batchInput(calls);

  // 空列表 / 超过 64 项
  assert.throws(() => wallet.createBatchApproval(batchInput([])), InvalidTransactionBatch);
  assert.throws(
    () => wallet.createBatchApproval(batchInput(makeCalls(MAX_BATCH_CALLS + 1))),
    InvalidTransactionBatch,
  );
  // 零地址 / 非法地址
  assert.throws(
    () => wallet.createBatchApproval(batchInput([{ ...calls[0]!, to: '0x' + '00'.repeat(20) }])),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.createBatchApproval(batchInput([{ ...calls[0]!, to: '0x1234' }])),
    InvalidTransactionBatch,
  );
  // 金额越界
  assert.throws(
    () => wallet.createBatchApproval(batchInput([{ ...calls[0]!, value: -1n }])),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.createBatchApproval(batchInput([{ ...calls[0]!, value: 2n ** 256n }])),
    InvalidTransactionBatch,
  );
  // data 不是 Uint8Array
  assert.throws(
    () =>
      wallet.createBatchApproval(
        batchInput([{ ...calls[0]!, data: 'abcd' as unknown as Uint8Array }]),
      ),
    InvalidTransactionBatch,
  );
  // nonce 跳号
  assert.throws(
    () => wallet.createBatchApproval({ ...base, nonce: 5n }),
    InvalidTransactionBatch,
  );
  // 全部失败不产生记录、不耗 nonce、不建任务
  assert.equal(wallet.listBatchApprovals().length, 0);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建批量审批：nonce 已用抛 NonceAlreadyUsedError（优先于过期），过期抛 RequestExpired', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(2);
  const input = batchInput(calls);
  const sigs = signBatchTransaction(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  wallet.submitBatchTransaction(input, sigs); // 消费 nonce 0

  // 已用 nonce + 已过期 deadline：仍报复用
  assert.throws(
    () => wallet.createBatchApproval({ ...input, deadline: 500n }),
    NonceAlreadyUsedError,
  );
  // 未用 nonce 但已过期
  assert.throws(
    () => wallet.createBatchApproval({ ...input, nonce: 1n, deadline: 500n }),
    RequestExpired,
  );
  assert.equal(wallet.listBatchApprovals().length, 0);
});

test('创建批量审批：deadline 恰好等于当前时间有效（“早于”才过期）', () => {
  const { wallet } = setup();
  const a = wallet.createBatchApproval(batchInput(makeCalls(1), { deadline: 1000n }));
  assert.equal(a.status, 'collecting');
});

// ---------- 加签 ----------

test('批量审批加签：逐个收集当前所有者签名，达到阈值后 ready，签名者按加签顺序', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);

  const mid = wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.equal(mid.status, 'collecting');
  assert.deepEqual(mid.signers, [ownerActors[0]!.address]);

  const ready = wallet.addBatchApprovalSignature(a.id, sigs[1]!);
  assert.equal(ready.status, 'ready');
  assert.deepEqual(ready.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);

  // 加签不改策略、nonce、队列
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);

  const queried = wallet.getBatchApproval(a.id);
  assert.equal(queried.status, 'ready');
  assert.deepEqual(queried.signers, ready.signers);
});

test('批量审批加签：同一所有者重复签名抛 DuplicateApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[0]!), DuplicateApprovalSignatureError);
  // 失败不变
  assert.equal(wallet.getBatchApproval(a.id).signers.length, 1);
});

test('批量审批加签：格式非法、摘要不符或签名者非所有者抛 InvalidApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);

  // 非 65 字节
  assert.throws(
    () => wallet.addBatchApprovalSignature(a.id, new Uint8Array(64)),
    InvalidApprovalSignatureError,
  );
  // 非所有者签名（外部密钥对审批摘要签名）
  const outsider = actors(1);
  const outsiderSig = signBatchApproval(outsider, { walletId: WALLET, version: 1n, ...input });
  assert.throws(
    () => wallet.addBatchApprovalSignature(a.id, outsiderSig[0]!),
    InvalidApprovalSignatureError,
  );
  // 摘要不符：直接提交域（safe-wallet/tx-batch/v1）的签名不能用于审批
  const directSigs = signBatchTransaction(ownerActors.slice(0, 1), { walletId: WALLET, ...input });
  assert.throws(
    () => wallet.addBatchApprovalSignature(a.id, directSigs[0]!),
    InvalidApprovalSignatureError,
  );
  // 摘要不符：普通交易审批域（safe-wallet/tx-approval/v1）的签名也不能用于批量审批
  const txApprovalSigs = signTransactionApproval(ownerActors.slice(0, 1), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: newbie.address,
  });
  assert.throws(
    () => wallet.addBatchApprovalSignature(a.id, txApprovalSigs[0]!),
    InvalidApprovalSignatureError,
  );
  // 全部失败后可继续正常加签
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  assert.equal(wallet.getBatchApproval(a.id).signers.length, 1);
});

test('批量审批签名不能用于直接 submitBatchTransaction（两域互不通用）', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  wallet.addBatchApprovalSignature(a.id, sigs[1]!);
  // 同一内容、同一批签名者：审批域签名无法授权直接提交
  assert.throws(() => wallet.submitBatchTransaction(input, sigs), InvalidTransactionBatch);
  assert.equal(wallet.tasks.length, 0);
});

test('未知批量审批 id：加签 / 查询 / 提交均抛 ApprovalNotFoundError', () => {
  const { wallet, ownerActors } = setup();
  const sigs = batchSigs(ownerActors, batchInput(makeCalls(1)), 1);
  assert.throws(() => wallet.addBatchApprovalSignature('nope', sigs[0]!), ApprovalNotFoundError);
  assert.throws(() => wallet.getBatchApproval('nope'), ApprovalNotFoundError);
  assert.throws(() => wallet.submitBatchApproval('nope'), ApprovalNotFoundError);
});

// ---------- 过期与版本漂移 ----------

test('批量审批过期：加签 / 提交抛 ApprovalExpiredError，查询状态 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = batchInput(makeCalls(2), { deadline: 2000n });
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
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
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
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

  const sigs = signBatchApproval(ownerActors.slice(0, 1), {
    walletId: WALLET,
    version: 1n,
    ...input,
  });
  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[0]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalExpiredError);
  assert.equal(wallet.getBatchApproval(a.id).status, 'expired');
});

// ---------- 提交 ----------

test('提交批量审批：按 tx-batch/v1 摘要入队一个任务，只消费创建时 nonce，执行产出原子批量回执', () => {
  const { wallet, ownerActors } = setup();
  const calls = makeCalls(3);
  const input = batchInput(calls);
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  wallet.addBatchApprovalSignature(a.id, sigs[1]!);

  const task = wallet.submitBatchApproval(a.id);
  assert.equal(task.status, 'queued');
  assert.equal(task.nonce, 0n);
  assert.equal(task.payload.kind, 'transaction-batch');
  if (task.payload.kind !== 'transaction-batch') throw new Error('payload kind narrowed');
  assert.equal(task.payload.calls.length, 3);
  assert.deepEqual(
    task.payload.calls.map((c) => c.to),
    calls.map((c) => c.to),
  );
  // 任务摘要是既有 safe-wallet/tx-batch/v1 域
  const directDigest = hashTransactionBatch({ walletId: WALLET, ...input });
  assert.equal(task.digest, directDigest.toString('hex'));

  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 1, '整批只入队一个任务');
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.getBatchApproval(a.id).status, 'submitted');

  // 执行成功：整批一个 transfer-batch 回执，顺序保留
  const executed = wallet.executeTask(task.id);
  assert.equal(executed.status, 'executed');
  const result = executed.receipt?.result as {
    kind: string;
    calls: { to: string; value: bigint; data: string }[];
  };
  assert.equal(result.kind, 'transfer-batch');
  assert.equal(result.calls.length, 3);
  assert.deepEqual(
    result.calls.map((c) => c.to),
    calls.map((c) => c.to),
  );
  assert.deepEqual(
    result.calls.map((c) => c.data),
    calls.map((c) => Buffer.from(c.data).toString('hex')),
  );
  // 终态幂等：重复执行返回既有状态
  const again = wallet.executeTask(task.id);
  assert.equal(again.status, 'executed');
});

test('提交后：加签 / 重复提交抛 ApprovalAlreadySubmittedError，查询 submitted', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 3);
  for (const s of sigs.slice(0, 2)) wallet.addBatchApprovalSignature(a.id, s);
  wallet.submitBatchApproval(a.id);

  assert.throws(() => wallet.addBatchApprovalSignature(a.id, sigs[2]!), ApprovalAlreadySubmittedError);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalAlreadySubmittedError);
  assert.equal(wallet.getBatchApproval(a.id).status, 'submitted');
});

test('提交批量审批：签名不足抛 ApprovalThresholdNotMetError，不消费 nonce、不建任务', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(1));
  const a = wallet.createBatchApproval(input);
  wallet.addBatchApprovalSignature(a.id, batchSigs(ownerActors, input, 1)[0]!);

  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.getBatchApproval(a.id).status, 'collecting');
});

test('提交批量审批：创建后 nonce 被其他提交消费 → NonceAlreadyUsedError，审批不建任务', () => {
  const { wallet, ownerActors } = setup();
  const input = batchInput(makeCalls(2));
  const a = wallet.createBatchApproval(input);
  for (const s of batchSigs(ownerActors, input, 2)) wallet.addBatchApprovalSignature(a.id, s);

  // 直接提交同一内容消费 nonce 0
  const directSigs = signBatchTransaction(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  wallet.submitBatchTransaction(input, directSigs);

  assert.throws(() => wallet.submitBatchApproval(a.id), NonceAlreadyUsedError);
  assert.equal(wallet.tasks.length, 1);
  // 审批仍为 ready（未提交、未过期、版本未漂移），可查询
  assert.equal(wallet.getBatchApproval(a.id).status, 'ready');
  assert.equal(wallet.expectedNonce, 1n);
});

test('同 nonce 多候选：提交其一后，另一候选提交抛 NonceAlreadyUsedError，且两候选独立', () => {
  const { wallet, ownerActors } = setup();
  const input1 = batchInput(makeCalls(2));
  const input2 = batchInput(makeCalls(2, 500n));
  const a1 = wallet.createBatchApproval(input1);
  const a2 = wallet.createBatchApproval(input2);
  for (const s of batchSigs(ownerActors, input1, 2)) wallet.addBatchApprovalSignature(a1.id, s);
  for (const s of batchSigs(ownerActors, input2, 2)) wallet.addBatchApprovalSignature(a2.id, s);
  assert.equal(wallet.getBatchApproval(a1.id).status, 'ready');
  assert.equal(wallet.getBatchApproval(a2.id).status, 'ready');

  const task = wallet.submitBatchApproval(a1.id);
  assert.equal(task.nonce, 0n);
  // 第二个候选：nonce 已被同批候选消费
  assert.throws(() => wallet.submitBatchApproval(a2.id), NonceAlreadyUsedError);
  // 第二个候选内容与状态不变，仍只有一个任务
  assert.equal(wallet.getBatchApproval(a2.id).status, 'ready');
  assert.equal(wallet.tasks.length, 1);
});

// ---------- 列表 ----------

test('listBatchApprovals：按创建顺序返回快照，与其他审批命名空间独立', () => {
  const { wallet } = setup();
  const input1 = batchInput(makeCalls(1));
  const input2 = batchInput(makeCalls(2, 500n));
  const a1 = wallet.createBatchApproval(input1);
  // 夹杂一个普通交易审批，不应出现在批量审批列表中
  const txA = wallet.createTransactionApproval({
    nonce: 0n,
    deadline: 9000n,
    to: newbie.address,
    value: 1n,
  });
  const a2 = wallet.createBatchApproval(input2);

  const list = wallet.listBatchApprovals();
  assert.equal(list.length, 2);
  assert.equal(list[0]!.id, a1.id);
  assert.equal(list[1]!.id, a2.id);
  assert.equal(list[1]!.calls.length, 2);

  // 命名空间互不可见
  assert.throws(() => wallet.getBatchApproval(txA.id), ApprovalNotFoundError);
  assert.throws(() => wallet.getTransactionApproval(a1.id), ApprovalNotFoundError);
});

// ---------- 与既有队列共存 ----------

test('批量审批任务与直接提交任务共用 FIFO：按入队顺序执行，取消与幂等语义不变', () => {
  const { wallet, ownerActors } = setup();
  // nonce 0：直接提交一笔批量交易
  const directInput = batchInput(makeCalls(2));
  const directSigs = signBatchTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    ...directInput,
  });
  const directTask = wallet.submitBatchTransaction(directInput, directSigs);

  // nonce 1：批量审批收集后提交入队
  const inputB = batchInput(makeCalls(2, 500n), { nonce: 1n });
  const b = wallet.createBatchApproval(inputB);
  for (const s of batchSigs(ownerActors, inputB, 2)) wallet.addBatchApprovalSignature(b.id, s);
  const taskB = wallet.submitBatchApproval(b.id);
  assert.equal(taskB.nonce, 1n);
  assert.equal(wallet.expectedNonce, 2n);

  // nonce 2：再登记一个批量审批并提交，随后取消该任务
  const inputC = batchInput(makeCalls(1, 900n), { nonce: 2n });
  const c = wallet.createBatchApproval(inputC);
  for (const s of batchSigs(ownerActors, inputC, 2)) wallet.addBatchApprovalSignature(c.id, s);
  const taskC = wallet.submitBatchApproval(c.id);

  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: taskC.digest,
    nonce: 3n,
    deadline: 9000n,
  });
  const cancelled = wallet.cancelTask(taskC.id, 3n, 9000n, cancelSigs);
  assert.equal(cancelled.status, 'cancelled');

  // FIFO：先执行直接批量，再执行审批批量；已取消任务被越过
  const first = wallet.executeNext();
  assert.equal(first?.id, directTask.id);
  assert.equal(first?.status, 'executed');
  const second = wallet.executeNext();
  assert.equal(second?.id, taskB.id);
  assert.equal(second?.status, 'executed');
  assert.equal((second?.receipt?.result as { kind: string }).kind, 'transfer-batch');
  assert.equal(wallet.executeNext(), null);
  // 取消终态幂等：重复执行返回既有状态
  assert.equal(wallet.executeTask(taskC.id).status, 'cancelled');
});

test('批量审批失败路径不留审批、任务、nonce 或策略变化', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = batchInput(makeCalls(2), { deadline: 2000n });
  const a = wallet.createBatchApproval(input);
  const sigs = batchSigs(ownerActors, input, 2);
  wallet.addBatchApprovalSignature(a.id, sigs[0]!);
  const before = {
    approvals: wallet.listBatchApprovals().length,
    tasks: wallet.tasks.length,
    nonce: wallet.expectedNonce,
    version: wallet.policyVersion,
  };

  // 过期后提交失败
  clock.set(2001n);
  assert.throws(() => wallet.submitBatchApproval(a.id), ApprovalExpiredError);
  // 签名不足（新审批）
  clock.set(1000n);
  const b = wallet.createBatchApproval(batchInput(makeCalls(1)));
  assert.throws(() => wallet.submitBatchApproval(b.id), ApprovalThresholdNotMetError);

  assert.equal(wallet.listBatchApprovals().length, before.approvals + 1); // 只有成功登记的两条
  assert.equal(wallet.tasks.length, before.tasks);
  assert.equal(wallet.expectedNonce, before.nonce);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.policyVersion, before.version);
});
