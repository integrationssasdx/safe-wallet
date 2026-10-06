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
  InvalidPolicyChange,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { hashPolicyApproval, hashPolicyChange } from '../src/encoding.ts';
import { generateKeyPair } from '../src/crypto.ts';
import {
  actors,
  addresses,
  fakeClock,
  signPolicyApproval,
  signPolicyChange,
  signTransaction,
  signTransactionApproval,
  type Actor,
} from './helpers.ts';

const WALLET = 'wallet-policy-approval';

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

type PolicyInput = {
  version: bigint;
  nonce: bigint;
  deadline: bigint;
  newOwners: string[];
  newConfirmations: bigint;
};

function policyInput(ownerActors: Actor[], overrides: Partial<PolicyInput> = {}): PolicyInput {
  return {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
    ...overrides,
  };
}

function policySigs(ownerActors: Actor[], input: PolicyInput, count = 2) {
  return signPolicyApproval(ownerActors.slice(0, count), {
    walletId: WALLET,
    ...input,
  });
}

// ---------- 创建 ----------

test('创建策略审批：返回完整快照，状态 collecting，不消费 nonce、不建任务、不改策略', () => {
  const { wallet, ownerActors } = setup();
  const before = {
    nonce: wallet.expectedNonce,
    version: wallet.policyVersion,
    owners: wallet.currentOwners,
    confirmations: wallet.requiredConfirmations,
  };
  const input = policyInput(ownerActors, {
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });

  const a = wallet.createPolicyApproval(input);
  assert.equal(typeof a.id, 'string');
  assert.ok(a.id.length > 0);
  assert.equal(a.version, 1n);
  assert.equal(a.confirmations, 2n); // 创建时的当前确认数
  assert.equal(a.nonce, 0n);
  assert.equal(a.deadline, 9000n);
  assert.deepEqual(a.newOwners, [ownerActors[0]!.address, newbie.address]);
  assert.equal(a.newConfirmations, 1n);
  assert.deepEqual(a.signers, []);
  assert.equal(a.status, 'collecting');

  // 摘要与 safe-wallet/policy-change-approval/v1 域一致
  const expected = hashPolicyApproval({ walletId: WALLET, ...input });
  assert.equal(a.digest, expected.toString('hex'));
  // 与直接提交的 safe-wallet/policy-change/v1 摘要不同
  const directDigest = hashPolicyChange({ walletId: WALLET, ...input });
  assert.notEqual(a.digest, directDigest.toString('hex'));

  // 登记不产生任何既有状态变化
  assert.equal(wallet.expectedNonce, before.nonce);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, before.version);
  assert.deepEqual(wallet.currentOwners, before.owners);
  assert.equal(wallet.requiredConfirmations, before.confirmations);
});

test('创建策略审批：新所有者顺序参与摘要绑定，顺序不同摘要不同', () => {
  const { wallet, ownerActors } = setup();
  const a = wallet.createPolicyApproval(
    policyInput(ownerActors, { newOwners: [ownerActors[0]!.address, ownerActors[1]!.address] }),
  );
  const b = wallet.createPolicyApproval(
    policyInput(ownerActors, { newOwners: [ownerActors[1]!.address, ownerActors[0]!.address] }),
  );
  assert.notEqual(a.digest, b.digest);
  assert.notEqual(a.id, b.id);
});

test('创建策略审批：同一 nonce 可登记多个候选（创建不消费 nonce），标识各不相同', () => {
  const { wallet, ownerActors } = setup();
  const a = wallet.createPolicyApproval(policyInput(ownerActors));
  const b = wallet.createPolicyApproval(
    policyInput(ownerActors, { newOwners: [ownerActors[0]!.address, newbie.address], newConfirmations: 1n }),
  );
  const c = wallet.createPolicyApproval(policyInput(ownerActors));
  assert.notEqual(a.id, b.id);
  assert.notEqual(b.id, c.id);
  // 内容完全相同的两个候选摘要一致，但 id 仍由创建序号区分
  assert.equal(a.digest, c.digest);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建策略审批：目标策略字段非法或版本不匹配抛 InvalidPolicyChange，失败不变', () => {
  const { wallet, ownerActors } = setup();
  const base = policyInput(ownerActors);

  // 新所有者为空
  assert.throws(
    () => wallet.createPolicyApproval({ ...base, newOwners: [] }),
    InvalidPolicyChange,
  );
  // 重复所有者
  assert.throws(
    () =>
      wallet.createPolicyApproval({
        ...base,
        newOwners: [ownerActors[0]!.address, ownerActors[0]!.address],
      }),
    InvalidPolicyChange,
  );
  // 零地址
  assert.throws(
    () =>
      wallet.createPolicyApproval({
        ...base,
        newOwners: [ownerActors[0]!.address, '0x' + '00'.repeat(20)],
      }),
    InvalidPolicyChange,
  );
  // 非法地址
  assert.throws(
    () => wallet.createPolicyApproval({ ...base, newOwners: ['0x1234'] }),
    InvalidPolicyChange,
  );
  // 确认数为 0 / 超过新所有者数量
  assert.throws(
    () => wallet.createPolicyApproval({ ...base, newConfirmations: 0n }),
    InvalidPolicyChange,
  );
  assert.throws(
    () =>
      wallet.createPolicyApproval({
        ...base,
        newOwners: [ownerActors[0]!.address],
        newConfirmations: 2n,
      }),
    InvalidPolicyChange,
  );
  // 版本不匹配
  assert.throws(
    () => wallet.createPolicyApproval({ ...base, version: 2n }),
    InvalidPolicyChange,
  );
  // nonce 跳号
  assert.throws(
    () => wallet.createPolicyApproval({ ...base, nonce: 5n }),
    InvalidPolicyChange,
  );
  // 全部失败不产生记录、不耗 nonce、不建任务
  assert.equal(wallet.listPolicyApprovals().length, 0);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('创建策略审批：nonce 已用抛 NonceAlreadyUsedError（优先于过期），过期抛 RequestExpired', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const sigs = signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  wallet.proposePolicyChange(input, sigs); // 消费 nonce 0

  // 已用 nonce + 已过期 deadline：仍报复用
  assert.throws(
    () => wallet.createPolicyApproval({ ...input, deadline: 500n }),
    NonceAlreadyUsedError,
  );
  // 未用 nonce 但已过期
  assert.throws(
    () => wallet.createPolicyApproval({ ...input, nonce: 1n, deadline: 500n }),
    RequestExpired,
  );
});

test('创建策略审批：deadline 恰好等于当前时间有效（“早于”才过期）', () => {
  const { wallet, ownerActors } = setup();
  const a = wallet.createPolicyApproval(policyInput(ownerActors, { deadline: 1000n }));
  assert.equal(a.status, 'collecting');
});

// ---------- 加签 ----------

test('策略审批加签：逐个收集当前所有者签名，达到阈值后 ready，签名者按加签顺序', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);

  const mid = wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  assert.equal(mid.status, 'collecting');
  assert.deepEqual(mid.signers, [ownerActors[0]!.address]);

  const ready = wallet.addPolicyApprovalSignature(a.id, sigs[1]!);
  assert.equal(ready.status, 'ready');
  assert.deepEqual(ready.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);

  // 加签不改策略、nonce、队列
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);

  const queried = wallet.getPolicyApproval(a.id);
  assert.equal(queried.status, 'ready');
  assert.deepEqual(queried.signers, ready.signers);
});

test('策略审批加签：同一所有者重复签名抛 DuplicateApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  assert.throws(() => wallet.addPolicyApprovalSignature(a.id, sigs[0]!), DuplicateApprovalSignatureError);
  // 失败不变
  assert.equal(wallet.getPolicyApproval(a.id).signers.length, 1);
});

test('策略审批加签：格式非法、摘要不符或签名者非所有者抛 InvalidApprovalSignatureError', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);

  // 非 65 字节
  assert.throws(
    () => wallet.addPolicyApprovalSignature(a.id, new Uint8Array(64)),
    InvalidApprovalSignatureError,
  );
  // 非所有者签名（外部密钥对审批摘要签名）
  const outsider = actors(1);
  const outsiderSig = signPolicyApproval(outsider, { walletId: WALLET, ...input });
  assert.throws(
    () => wallet.addPolicyApprovalSignature(a.id, outsiderSig[0]!),
    InvalidApprovalSignatureError,
  );
  // 摘要不符：直接提交域（safe-wallet/policy-change/v1）的签名不能用于审批
  const directSigs = signPolicyChange(ownerActors.slice(0, 1), { walletId: WALLET, ...input });
  assert.throws(
    () => wallet.addPolicyApprovalSignature(a.id, directSigs[0]!),
    InvalidApprovalSignatureError,
  );
  // 摘要不符：普通交易审批域（safe-wallet/tx-approval/v1）的签名也不能用于策略审批
  const txApprovalSigs = signTransactionApproval(ownerActors.slice(0, 1), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: newbie.address,
  });
  assert.throws(
    () => wallet.addPolicyApprovalSignature(a.id, txApprovalSigs[0]!),
    InvalidApprovalSignatureError,
  );
  // 全部失败后可继续正常加签
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  assert.equal(wallet.getPolicyApproval(a.id).signers.length, 1);
});

test('策略审批签名不能用于直接 proposePolicyChange（两域互不通用）', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  wallet.addPolicyApprovalSignature(a.id, sigs[1]!);
  // 同一内容、同一批签名者：审批域签名无法授权直接提交
  assert.throws(() => wallet.proposePolicyChange(input, sigs), InvalidPolicyChange);
  assert.equal(wallet.tasks.length, 0);
});

test('未知策略审批 id：加签 / 查询 / 提交均抛 ApprovalNotFoundError', () => {
  const { wallet, ownerActors } = setup();
  const sigs = policySigs(ownerActors, policyInput(ownerActors), 1);
  assert.throws(() => wallet.addPolicyApprovalSignature('nope', sigs[0]!), ApprovalNotFoundError);
  assert.throws(() => wallet.getPolicyApproval('nope'), ApprovalNotFoundError);
  assert.throws(() => wallet.submitApprovedPolicyChange('nope'), ApprovalNotFoundError);
});

// ---------- 过期与版本漂移 ----------

test('策略审批过期：加签 / 提交抛 ApprovalExpiredError，查询状态 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = policyInput(ownerActors, { deadline: 2000n });
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  clock.set(2001n);

  assert.throws(() => wallet.addPolicyApprovalSignature(a.id, sigs[1]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), ApprovalExpiredError);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'expired');
  // 失败不变
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

/** 通过直接策略变更让版本漂移（审批不消费 nonce，故用 nonce 0；版本 1 → 2） */
function driftPolicy(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const input = policyInput(ownerActors);
  const sigs = signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  const task = wallet.proposePolicyChange(input, sigs);
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
}

test('策略审批版本漂移：加签 / 提交抛 ApprovalPolicyConflictError，查询状态 conflicted', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);

  driftPolicy(wallet, ownerActors);

  assert.throws(() => wallet.addPolicyApprovalSignature(a.id, sigs[1]!), ApprovalPolicyConflictError);
  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), ApprovalPolicyConflictError);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'conflicted');
});

test('策略审批过期优先于版本冲突：同时发生时抛 ApprovalExpiredError，查询 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const input = policyInput(ownerActors, { deadline: 2000n });
  const a = wallet.createPolicyApproval(input);
  driftPolicy(wallet, ownerActors);
  clock.set(3000n);

  const sigs = policySigs(ownerActors, input, 1);
  assert.throws(() => wallet.addPolicyApprovalSignature(a.id, sigs[0]!), ApprovalExpiredError);
  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), ApprovalExpiredError);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'expired');
});

// ---------- 提交 ----------

test('提交策略审批：按 policy-change/v1 摘要入队，只消费创建时 nonce，提交时不改策略', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors, {
    newOwners: [ownerActors[2]!.address, ownerActors[0]!.address, newbie.address],
    newConfirmations: 2n,
  });
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 2);
  wallet.addPolicyApprovalSignature(a.id, sigs[0]!);
  wallet.addPolicyApprovalSignature(a.id, sigs[1]!);

  const task = wallet.submitApprovedPolicyChange(a.id);
  assert.equal(task.status, 'queued');
  assert.equal(task.nonce, 0n);
  assert.equal(task.payload.kind, 'policy-change');
  if (task.payload.kind !== 'policy-change') throw new Error('payload kind narrowed');
  assert.equal(task.payload.version, 1n);
  assert.deepEqual(task.payload.newOwners, input.newOwners);
  assert.equal(task.payload.newConfirmations, 2n);
  // 任务摘要是既有 safe-wallet/policy-change/v1 域
  const directDigest = hashPolicyChange({ walletId: WALLET, ...input });
  assert.equal(task.digest, directDigest.toString('hex'));

  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.expectedNonce, 1n);
  // 入队不等于生效：执行前策略保持原样
  assert.equal(wallet.policyVersion, 1n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'submitted');

  // 执行成功：原子替换所有者/确认数，版本递增，新所有者顺序保留
  const executed = wallet.executeTask(task.id);
  assert.equal(executed.status, 'executed');
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, input.newOwners);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(executed.receipt?.result, {
    kind: 'policy-applied',
    version: 2n,
    owners: input.newOwners,
    confirmations: 2n,
  });
});

test('提交后：加签 / 重复提交抛 ApprovalAlreadySubmittedError，查询 submitted', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  const sigs = policySigs(ownerActors, input, 3);
  for (const s of sigs.slice(0, 2)) wallet.addPolicyApprovalSignature(a.id, s);
  wallet.submitApprovedPolicyChange(a.id);

  assert.throws(() => wallet.addPolicyApprovalSignature(a.id, sigs[2]!), ApprovalAlreadySubmittedError);
  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), ApprovalAlreadySubmittedError);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'submitted');
});

test('提交策略审批：签名不足抛 ApprovalThresholdNotMetError，不消费 nonce、不建任务', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  wallet.addPolicyApprovalSignature(a.id, policySigs(ownerActors, input, 1)[0]!);

  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.getPolicyApproval(a.id).status, 'collecting');
});

test('提交策略审批：创建后 nonce 被其他提交消费 → NonceAlreadyUsedError，审批不建任务', () => {
  const { wallet, ownerActors } = setup();
  const input = policyInput(ownerActors);
  const a = wallet.createPolicyApproval(input);
  for (const s of policySigs(ownerActors, input, 2)) wallet.addPolicyApprovalSignature(a.id, s);

  // 直接提交同一内容消费 nonce 0
  const directSigs = signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...input });
  wallet.proposePolicyChange(input, directSigs);

  assert.throws(() => wallet.submitApprovedPolicyChange(a.id), NonceAlreadyUsedError);
  assert.equal(wallet.tasks.length, 1);
  // 审批仍为 ready（未提交、未过期、版本未漂移），可查询
  assert.equal(wallet.getPolicyApproval(a.id).status, 'ready');
  assert.equal(wallet.expectedNonce, 1n);
});

test('同 nonce 多候选：提交其一后，另一候选提交抛 NonceAlreadyUsedError，且两候选独立', () => {
  const { wallet, ownerActors } = setup();
  const input1 = policyInput(ownerActors);
  const input2 = policyInput(ownerActors, {
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });
  const a1 = wallet.createPolicyApproval(input1);
  const a2 = wallet.createPolicyApproval(input2);
  for (const s of policySigs(ownerActors, input1, 2)) wallet.addPolicyApprovalSignature(a1.id, s);
  for (const s of policySigs(ownerActors, input2, 2)) wallet.addPolicyApprovalSignature(a2.id, s);
  assert.equal(wallet.getPolicyApproval(a1.id).status, 'ready');
  assert.equal(wallet.getPolicyApproval(a2.id).status, 'ready');

  const task = wallet.submitApprovedPolicyChange(a1.id);
  assert.equal(task.nonce, 0n);
  // 第二个候选：nonce 已被同批候选消费
  assert.throws(() => wallet.submitApprovedPolicyChange(a2.id), NonceAlreadyUsedError);
  // 第二个候选内容与状态不变，仍只有一个任务
  assert.equal(wallet.getPolicyApproval(a2.id).status, 'ready');
  assert.equal(wallet.tasks.length, 1);
});

test('提交入队后执行时版本漂移：审批任务按既有 PolicyConflict 失败，策略不改', () => {
  const { wallet, ownerActors } = setup();
  // nonce 0：直接提交策略变更 A（version 1）入队但先不执行
  const inputA = policyInput(ownerActors);
  const sigsA = signPolicyChange(ownerActors.slice(0, 2), { walletId: WALLET, ...inputA });
  const taskA = wallet.proposePolicyChange(inputA, sigsA);

  // nonce 1：审批 B 同样绑定 version 1（创建时 A 尚未执行，版本仍为 1）
  const inputB = policyInput(ownerActors, {
    nonce: 1n,
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });
  const b = wallet.createPolicyApproval(inputB);
  for (const s of policySigs(ownerActors, inputB, 2)) wallet.addPolicyApprovalSignature(b.id, s);
  const taskB = wallet.submitApprovedPolicyChange(b.id);

  // 先执行队首 A：版本 1 → 2
  const doneA = wallet.executeTask(taskA.id);
  assert.equal(doneA.status, 'executed');
  assert.equal(wallet.policyVersion, 2n);

  // 再执行 B：绑定版本 1 ≠ 当前版本 2 → 既有 PolicyConflict 失败终态
  const doneB = wallet.executeTask(taskB.id);
  assert.equal(doneB.status, 'failed');
  assert.equal(doneB.receipt?.failureReason, 'PolicyConflict');
  // 策略保持 A 生效后的结果，B 的目标策略未应用，版本不再递增
  assert.equal(wallet.policyVersion, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
  assert.equal(wallet.requiredConfirmations, 2n);
});

// ---------- 列表 ----------

test('listPolicyApprovals：按创建顺序返回快照，与普通交易审批命名空间独立', () => {
  const { wallet, ownerActors } = setup();
  const input1 = policyInput(ownerActors);
  const input2 = policyInput(ownerActors, {
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });
  const a1 = wallet.createPolicyApproval(input1);
  // 夹杂一个普通交易审批，不应出现在策略审批列表中
  const txA = wallet.createTransactionApproval({
    nonce: 0n,
    deadline: 9000n,
    to: newbie.address,
    value: 1n,
  });
  const a2 = wallet.createPolicyApproval(input2);

  const list = wallet.listPolicyApprovals();
  assert.equal(list.length, 2);
  assert.equal(list[0]!.id, a1.id);
  assert.equal(list[1]!.id, a2.id);
  assert.deepEqual(list[1]!.newOwners, input2.newOwners);

  // 两个命名空间互不可见
  assert.throws(() => wallet.getPolicyApproval(txA.id), ApprovalNotFoundError);
  assert.throws(() => wallet.getTransactionApproval(a1.id), ApprovalNotFoundError);
});

// ---------- 与既有队列共存 ----------

test('策略审批任务与直接提交任务共用 FIFO：按入队顺序执行', () => {
  const { wallet, ownerActors } = setup();
  // nonce 0：直接提交一笔普通交易（不改变策略版本）
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: newbie.address,
    value: 1n,
  });
  const txTask = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: newbie.address, value: 1n },
    txSigs,
  );

  // nonce 1：策略变更审批收集后提交入队（绑定 version 1；普通交易不推进版本，故可成功执行）
  const inputB = policyInput(ownerActors, { nonce: 1n, newConfirmations: 2n });
  const b = wallet.createPolicyApproval(inputB);
  for (const s of policySigs(ownerActors, inputB, 2)) wallet.addPolicyApprovalSignature(b.id, s);
  const taskB = wallet.submitApprovedPolicyChange(b.id);
  assert.equal(taskB.nonce, 1n);
  assert.equal(wallet.expectedNonce, 2n);

  const first = wallet.executeNext();
  assert.equal(first?.id, txTask.id);
  assert.equal(first?.status, 'executed');
  assert.equal(wallet.policyVersion, 1n);
  const second = wallet.executeNext();
  assert.equal(second?.id, taskB.id);
  assert.equal(second?.status, 'executed');
  assert.equal(wallet.policyVersion, 2n);
});
