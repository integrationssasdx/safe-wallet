import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import {
  ApprovalExpiredError,
  ApprovalNotFoundError,
  ApprovalRevocationConflictError,
  ApprovalRevocationThresholdNotMetError,
  InvalidApprovalRevocationNonceError,
  InvalidApprovalRevocationRequest,
  InvalidApprovalRevocationSigner,
  InvalidApprovalSignatureError,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import {
  hashApprovalRevocation,
  hashCancellation,
  hashPolicyChange,
  hashTransactionApproval,
} from '../src/encoding.ts';
import { generateKeyPair, signDigest } from '../src/crypto.ts';
import {
  actors,
  addresses,
  fakeClock,
  signApprovalRevocation,
  signCancellation,
  signTransaction,
  signTransactionApproval,
  type Actor,
} from './helpers.ts';

const WALLET = 'wallet-revoke';

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

/** 撤销签名（默认 nonce 0、deadline 9000、前 count 个所有者） */
function revokeSigs(
  ownerActors: Actor[],
  approvalDigest: string,
  opts: { nonce?: bigint; deadline?: bigint; count?: number; walletId?: string } = {},
): Buffer[] {
  return signApprovalRevocation(ownerActors.slice(0, opts.count ?? 2), {
    walletId: opts.walletId ?? WALLET,
    approvalDigest,
    nonce: opts.nonce ?? 0n,
    deadline: opts.deadline ?? 9000n,
  });
}

type AnyApproval = { id: string; digest: string; status: string; signers: string[] };

// ---------- 三类审批均可撤销 ----------

test('撤销普通交易审批：返回 revoked 快照，保留签名者但失效；不建任务、只消费一次 nonce', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  // 先加一个签名
  wallet.addApprovalSignature(
    approval.id,
    signTransactionApproval(ownerActors.slice(0, 1), {
      walletId: WALLET,
      version: 1n,
      nonce: 0n,
      deadline: 9000n,
      to: TO,
      value: 7n,
    })[0]!,
  );

  const policyBefore = wallet.policy;
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  assert.equal(revoked.id, approval.id);
  assert.equal(revoked.digest, approval.digest);
  assert.equal(revoked.status, 'revoked');
  // 原审批已收集签名者保留
  assert.equal(revoked.signers.length, 1);
  assert.equal(revoked.signers[0], ownerActors[0]!.address);

  // 只消费一次撤销 nonce
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.expectedNonce, 1n);
  // 不建任务、不改策略
  assert.equal(wallet.tasks.length, 0);
  assert.deepEqual(wallet.policy, policyBefore);
  // 查询一致
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'revoked');
});

test('撤销策略变更审批：revoked 终态，目标策略与版本不变', () => {
  const { wallet, ownerActors } = setup();
  const newbie = generateKeyPair();
  const approval = wallet.createPolicyApproval({
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  });
  const revoked = wallet.revokeApproval(
    approval.id,
    0n,
    9000n,
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.currentOwners.length, 3);
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.getPolicyApproval(approval.id).status, 'revoked');
});

test('撤销批量交易审批：revoked 终态，calls 保留、无任务无回执', () => {
  const { wallet, ownerActors } = setup();
  const calls = [
    { to: TO, value: 100n, data: new Uint8Array() },
    { to: generateKeyPair().address, value: 200n, data: Buffer.from('data') },
  ];
  const approval = wallet.createBatchApproval({ nonce: 0n, deadline: 9000n, calls });
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.getBatchApproval(approval.id).calls.length, 2);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 1n);
  // 列表中状态同样为 revoked
  assert.equal(wallet.listBatchApprovals()[0]!.status, 'revoked');
});

test('ready（已达阈值）的未提交审批仍可撤销', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const approvalSigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  wallet.addApprovalSignature(approval.id, approvalSigs[0]!);
  wallet.addApprovalSignature(approval.id, approvalSigs[1]!);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');

  // 撤销 nonce 必须是当前期望 nonce 0（创建未消费）
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.expectedNonce, 1n);
});

// ---------- expired / conflicted 仍可撤销，revoked 优先 ----------

test('已过期（expired）的审批仍可撤销；撤销后状态为 revoked 而非 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 2000n, to: TO, value: 7n });
  clock.set(3000n);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'expired');

  // 加签应被 expired 拦截（撤销前行为不变）
  assert.throws(
    () =>
      wallet.addApprovalSignature(
        approval.id,
        signTransactionApproval(ownerActors.slice(0, 1), {
          walletId: WALLET,
          version: 1n,
          nonce: 0n,
          deadline: 2000n,
          to: TO,
          value: 7n,
        })[0]!,
      ),
    ApprovalExpiredError,
  );

  // 撤销请求自身 deadline 未过即可；目标审批已过期不影响
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest, { deadline: 9000n }),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'revoked');
});

test('版本漂移（conflicted）的审批仍可撤销；撤销后状态为 revoked 而非 conflicted', () => {
  const { wallet, ownerActors } = setup();
  // 登记策略审批
  const approval = wallet.createPolicyApproval({
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  // 登记策略审批不消费 nonce，故可直接以 nonce 0 提交一个策略变更使版本漂移
  const pcInput = {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const directSigs = ownerActors
    .slice(0, 2)
    .map((k) => signDigest(k.privateKey, hashPolicyChange({ walletId: WALLET, ...pcInput })));
  const task = wallet.proposePolicyChange(pcInput, directSigs);
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.getPolicyApproval(approval.id).status, 'conflicted');
  assert.equal(wallet.expectedNonce, 1n);

  // 撤销一个版本漂移的审批：撤销 nonce 为当前期望 1，阈值按当前确认数 1
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest, { nonce: 1n, count: 1 }),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.expectedNonce, 2n);
  assert.equal(wallet.policyVersion, 2n);
});

// ---------- 校验顺序 ----------

test('字段非法：approvalId 非字符串/空、签名集合畸形 → InvalidApprovalRevocationRequest', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const goodSigs = revokeSigs(ownerActors, approval.digest);

  for (const badId of [undefined, null, 42, {}, [], '']) {
    assert.throws(
      () => wallet.revokeApproval({ approvalId: badId as any, nonce: 0n, deadline: 9000n }, goodSigs),
      InvalidApprovalRevocationRequest,
    );
  }
  for (const badSigs of [
    undefined,
    null,
    'x',
    [],
    [null],
    ['deadbeef'],
    [new Uint8Array(64)],
    [new Uint8Array(65).fill(0xff)], // 65 字节但不可解析
    [new Uint8Array(65), goodSigs[0]],
  ]) {
    assert.throws(
      () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, badSigs as any),
      InvalidApprovalRevocationRequest,
    );
  }
  // nonce / deadline 畸形也归为请求错误
  for (const bad of [undefined, 'abc', -1.5, {}, 2n ** 300n]) {
    assert.throws(
      () => wallet.revokeApproval({ approvalId: approval.id, nonce: bad as any, deadline: 9000n }, goodSigs),
      InvalidApprovalRevocationRequest,
    );
    assert.throws(
      () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: bad as any }, goodSigs),
      InvalidApprovalRevocationRequest,
    );
  }
  // 任何字段失败都不消费 nonce
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
});

test('校验顺序：nonce 复用 → NonceAlreadyUsedError（优先于过期/错序/审批不存在）', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  // 先用一次合法撤销消费 nonce 0
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  const other = wallet.createTransactionApproval({ nonce: 1n, deadline: 9000n, to: TO, value: 8n });
  // 重放 nonce 0：即使 deadline 已过、即使 nonce 错序、即使目标审批已撤销，也恒定报复用
  const replay = revokeSigs(ownerActors, other.digest, { nonce: 0n, deadline: 1n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: other.id, nonce: 0n, deadline: 1n }, replay),
    NonceAlreadyUsedError,
  );
});

test('校验顺序：deadline 过期 → RequestExpired（优先于错序/不存在/签名）', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  // 未使用的 nonce 5（错序）+ 过期 deadline + 不存在的审批 id + 任意签名 → 必须报 RequestExpired
  const sigs = revokeSigs(ownerActors, approval.digest, { nonce: 5n, deadline: 1n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: 'nope', nonce: 5n, deadline: 1n }, sigs),
    RequestExpired,
  );
});

test('校验顺序：nonce 错序 → InvalidApprovalRevocationNonceError（优先于不存在/状态/签名）', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const sigs = revokeSigs(ownerActors, approval.digest, { nonce: 5n, deadline: 9000n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: 'nope', nonce: 5n, deadline: 9000n }, sigs),
    InvalidApprovalRevocationNonceError,
  );
  // 回退 nonce（负数非法归 InvalidApprovalRevocationRequest；这里用未用但小于期望的情形由推进后构造）
  assert.equal(wallet.expectedNonce, 0n);
});

test('校验顺序：审批不存在 → ApprovalNotFoundError（优先于签名校验）', () => {
  const { wallet } = setup();
  // nonce 顺序正确（0）、未过期，但 id 不存在；即使签名是乱填的也必须报 NotFound
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: 'deadbeefdeadbeef', nonce: 0n, deadline: 9000n },
        [new Uint8Array(65).fill(0x01), new Uint8Array(65).fill(0x02)],
      ),
    ApprovalNotFoundError,
  );
});

test('校验顺序：已提交审批 → ApprovalRevocationConflictError（不消费撤销 nonce）', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const aSigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  wallet.addApprovalSignature(approval.id, aSigs[0]!);
  wallet.addApprovalSignature(approval.id, aSigs[1]!);
  const task = wallet.submitApprovedTransaction(approval.id); // 消费 nonce 0
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(task.status, 'queued');

  // 已提交审批不可撤销：撤销 nonce 1 顺序正确，仍报冲突，且不消费 nonce 1
  const sigs = revokeSigs(ownerActors, approval.digest, { nonce: 1n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 1n, deadline: 9000n }, sigs),
    ApprovalRevocationConflictError,
  );
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(1n), false);
  // 既有任务不受影响
  assert.equal(wallet.getTask(task.id)?.status, 'queued');
});

test('签名与摘要不匹配 / 签名者非所有者 → InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });

  // 非所有者（65 字节合法签名）
  const outsiders = actors(2);
  const outsiderSigs = revokeSigs(outsiders, approval.digest);
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, outsiderSigs),
    InvalidApprovalRevocationSigner,
  );

  // 为另一个审批摘要签的名（跨审批）
  const other = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 8n });
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, other.digest),
      ),
    InvalidApprovalRevocationSigner,
  );

  // 一个所有者 + 一个局外人：恢复后局外人即拒
  const mixed = [
    revokeSigs(ownerActors.slice(0, 1), approval.digest)[0]!,
    revokeSigs(outsiders.slice(1, 2), approval.digest)[0]!,
  ];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, mixed),
    InvalidApprovalRevocationSigner,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('去重签名不足当前确认数 → ApprovalRevocationThresholdNotMetError', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  // 只有一个 distinct 所有者（重复签名去重后仍为 1 < 2）
  const one = revokeSigs(ownerActors.slice(0, 1), approval.digest);
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, one),
    ApprovalRevocationThresholdNotMetError,
  );
  const dup = [...revokeSigs(ownerActors.slice(0, 1), approval.digest), ...one];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, dup),
    ApprovalRevocationThresholdNotMetError,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('阈值按当前确认数/当前所有者：策略变更后旧所有者的撤销签名无效', () => {
  // 3 所有者阈值 2 → 执行策略变更为 2 所有者阈值 1（含一名新所有者）
  const outer = setup(3, 2n);
  const { wallet, ownerActors } = outer;
  const newbie = generateKeyPair();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });

  // 先让策略漂移：nonce 0 直接策略变更（同审批共享 nonce 序列，创建不消费，故 nonce 0 可用于提交）
  const pcInput = {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: [ownerActors[0]!.address, newbie.address],
    newConfirmations: 1n,
  };
  const pcSigs = ownerActors
    .slice(0, 2)
    .map((k) => signDigest(k.privateKey, hashPolicyChange({ walletId: WALLET, ...pcInput })));
  const task = wallet.proposePolicyChange(pcInput, pcSigs);
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.expectedNonce, 1n);
  // 审批现在 conflicted，但仍可撤销；阈值按当前确认数 1、签名者须为当前所有者
  // 被移除的旧所有者 ownerActors[1] 签名无效
  const removedSigs = [signDigest(ownerActors[1]!.privateKey, hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 1n,
    deadline: 9000n,
  }))];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 1n, deadline: 9000n }, removedSigs),
    InvalidApprovalRevocationSigner,
  );
  // 新所有者单独一个签名即达当前阈值 1
  const newbieSig = [signDigest(newbie.privateKey, hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 1n,
    deadline: 9000n,
  }))];
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: 9000n },
    newbieSig,
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.expectedNonce, 2n);
});

// ---------- 域隔离 ----------

test('跨钱包撤销签名无效 → InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const sigs = revokeSigs(ownerActors, approval.digest, { walletId: 'other-wallet' });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, sigs),
    InvalidApprovalRevocationSigner,
  );
});

test('其他操作域的签名不能用于撤销', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });

  // 审批加签域（safe-wallet/tx-approval/v1）
  const approvalDomainSigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, approvalDomainSigs),
    InvalidApprovalRevocationSigner,
  );

  // 直接交易域（safe-wallet/tx/v1）
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
  });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, txSigs),
    InvalidApprovalRevocationSigner,
  );

  // 任务取消域（safe-wallet/cancel/v1）：把 approvalDigest 位置当 taskDigest 签
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, cancelSigs),
    InvalidApprovalRevocationSigner,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('撤销签名也不能用于审批加签或直接提交（域对称隔离）', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const revokeSig = revokeSigs(ownerActors.slice(0, 1), approval.digest)[0]!;
  // 撤销域签名拿去加签 → 无效签名
  assert.throws(
    () => wallet.addApprovalSignature(approval.id, revokeSig),
    InvalidApprovalSignatureError,
  );
});

test('撤销摘要绑定 approvalDigest/nonce/deadline/walletId：任一变化摘要不同', () => {
  const base = { walletId: WALLET, approvalDigest: '0x' + 'ab'.repeat(32), nonce: 0n, deadline: 9000n };
  const h0 = hashApprovalRevocation(base);
  for (const v of [
    { ...base, walletId: 'other' },
    { ...base, approvalDigest: '0x' + 'cd'.repeat(32) },
    { ...base, nonce: 1n },
    { ...base, deadline: 9001n },
  ]) {
    assert.ok(!hashApprovalRevocation(v).equals(h0));
  }
  // 与取消域不同（即使 walletId/摘要/nonce/deadline 数值相同）
  const cancel = hashCancellation({
    walletId: WALLET,
    taskDigest: base.approvalDigest,
    nonce: 0n,
    deadline: 9000n,
  });
  assert.ok(!h0.equals(cancel));
  // 与审批创建域不同
  const ap = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  assert.ok(!h0.equals(ap));
});

// ---------- 撤销后的终态行为 ----------

test('撤销后：加签 / 提交 / 再撤销统一抛 ApprovalRevocationConflictError', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  const approvalSig = signTransactionApproval(ownerActors.slice(0, 1), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  })[0]!;
  assert.throws(() => wallet.addApprovalSignature(approval.id, approvalSig), ApprovalRevocationConflictError);
  assert.throws(() => wallet.submitApprovedTransaction(approval.id), ApprovalRevocationConflictError);

  // 再撤销：nonce 1 合法且签名正确，仍因目标已撤销报冲突，且不消费 nonce 1
  const again = revokeSigs(ownerActors, approval.digest, { nonce: 1n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 1n, deadline: 9000n }, again),
    ApprovalRevocationConflictError,
  );
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(1n), false);
});

test('撤销后：原审批签名保留可见但失效，且不受后来过期影响（revoked 优先于 expired）', () => {
  const { wallet, ownerActors, clock } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 2000n, to: TO, value: 7n });
  wallet.addApprovalSignature(
    approval.id,
    signTransactionApproval(ownerActors.slice(0, 1), {
      walletId: WALLET,
      version: 1n,
      nonce: 0n,
      deadline: 2000n,
      to: TO,
      value: 7n,
    })[0]!,
  );
  // 在审批过期前撤销（撤销 deadline 1500）
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 1500n },
    revokeSigs(ownerActors, approval.digest, { deadline: 1500n }),
  );
  assert.equal(revoked.signers.length, 1);
  // 时钟越过审批与撤销的 deadline
  clock.set(5000n);
  const snap = wallet.getTransactionApproval(approval.id);
  assert.equal(snap.status, 'revoked'); // revoked 优先于 expired
  assert.equal(snap.signers.length, 1);
  assert.throws(
    () =>
      wallet.addApprovalSignature(
        approval.id,
        signTransactionApproval(ownerActors.slice(0, 1), {
          walletId: WALLET,
          version: 1n,
          nonce: 0n,
          deadline: 2000n,
          to: TO,
          value: 7n,
        })[0]!,
      ),
    ApprovalRevocationConflictError,
  );
});

test('撤销不影响未撤销审批与既有任务：提交/执行/批量/队列行为不变', () => {
  const { wallet, ownerActors } = setup();
  // 两个候选审批绑定同一 nonce 0
  const a1 = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const a2 = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 8n });
  // 撤销 a1（消费 nonce 0）
  wallet.revokeApproval(
    { approvalId: a1.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, a1.digest),
  );
  assert.equal(wallet.getTransactionApproval(a1.id).status, 'revoked');
  // a2 未受影响：仍是 collecting；但其绑定 nonce 0 已被撤销消费，提交时按既有 NonceAlreadyUsed 拒绝
  const a2Snap = wallet.getTransactionApproval(a2.id);
  assert.equal(a2Snap.status, 'collecting');
  const a2sigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 8n,
  });
  wallet.addApprovalSignature(a2.id, a2sigs[0]!);
  wallet.addApprovalSignature(a2.id, a2sigs[1]!);
  assert.throws(() => wallet.submitApprovedTransaction(a2.id), NonceAlreadyUsedError);

  // 之后可用 nonce 1 正常直接提交并执行，队列/FIFO/执行结果不变
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 1n,
    deadline: 9000n,
    to: TO,
    value: 42n,
  });
  const task = wallet.submitTransaction({ nonce: 1n, deadline: 9000n, to: TO, value: 42n }, txSigs);
  const done = wallet.executeTask(task.id);
  assert.equal(done.status, 'executed');
  assert.equal(wallet.expectedNonce, 2n);
});

test('已提交任务仍只能经 cancelTask 取消：撤销不对已提交任务生效', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const aSigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  wallet.addApprovalSignature(approval.id, aSigs[0]!);
  wallet.addApprovalSignature(approval.id, aSigs[1]!);
  const task = wallet.submitApprovedTransaction(approval.id);
  // cancelTask（nonce 1）正常取消该任务
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: task.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  const cancelled = wallet.cancelTask(task.id, 1n, 9000n, cancelSigs);
  assert.equal(cancelled.status, 'cancelled');
  // 审批仍为 submitted（撤销对它报冲突）
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'submitted');
  const revokeSigs2 = revokeSigs(ownerActors, approval.digest, { nonce: 2n });
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 2n, deadline: 9000n }, revokeSigs2),
    ApprovalRevocationConflictError,
  );
});

test('位置参数重载与对象参数等价', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const snap = wallet.revokeApproval(
    approval.id,
    0n,
    9000n,
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(snap.status, 'revoked');
});

test('对抗输入：撤销路径不泄漏原生 TypeError/RangeError', () => {
  const { wallet, ownerActors } = setup();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: 9000n, to: TO, value: 7n });
  const allowed = new Set([
    InvalidApprovalRevocationRequest.name,
    InvalidApprovalRevocationSigner.name,
    ApprovalRevocationThresholdNotMetError.name,
    InvalidApprovalRevocationNonceError.name,
    NonceAlreadyUsedError.name,
    RequestExpired.name,
    ApprovalNotFoundError.name,
    ApprovalRevocationConflictError.name,
  ]);
  const garbage: unknown[] = [undefined, null, 'abc', -1.5, Number.NaN, {}, [], 2n ** 300n];
  for (const g of garbage) {
    for (const field of ['nonce', 'deadline'] as const) {
      const sub: Record<string, unknown> = { approvalId: approval.id, nonce: 0n, deadline: 9000n };
      sub[field] = g;
      assert.throws(
        () =>
          wallet.revokeApproval(
            sub as any,
            revokeSigs(ownerActors, approval.digest),
          ),
        (err: unknown) => allowed.has((err as Error).name),
      );
    }
  }
});
