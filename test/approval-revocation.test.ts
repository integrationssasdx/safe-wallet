import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import {
  ApprovalAlreadySubmittedError,
  ApprovalExpiredError,
  ApprovalNotFoundError,
  ApprovalPolicyConflictError,
  ApprovalRevocationConflictError,
  ApprovalRevocationThresholdNotMetError,
  InvalidApprovalRevocationNonceError,
  InvalidApprovalRevocationRequest,
  InvalidApprovalRevocationSigner,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import {
  hashApprovalRevocation,
  hashBatchApproval,
  hashCancellation,
  hashPolicyApproval,
  hashPolicyChange,
  hashTransaction,
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

const WALLET = 'wallet-approval-revoke';
const OTHER_WALLET = 'wallet-other';

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
const newbie = generateKeyPair();

// ---------- 三类审批的构造辅助 ----------

function txInput(overrides: { nonce?: bigint; deadline?: bigint; value?: bigint } = {}) {
  return { nonce: 0n, deadline: 9000n, to: TO, value: 7n, ...overrides };
}

function createTxReady(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const approval = wallet.createTransactionApproval(txInput());
  for (const k of ownerActors.slice(0, 2)) {
    wallet.addApprovalSignature(
      approval.id,
      signDigest(
        k.privateKey,
        hashTransactionApproval({
          walletId: WALLET,
          version: 1n,
          nonce: 0n,
          deadline: 9000n,
          to: TO,
          value: 7n,
          data: new Uint8Array(),
        }),
      ),
    );
  }
  return approval;
}

function policyInput(ownerActors: Actor[]) {
  return {
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  };
}

function createPolicyReady(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const input = policyInput(ownerActors);
  const approval = wallet.createPolicyApproval(input);
  
  for (const k of ownerActors.slice(0, 2)) {
    wallet.addPolicyApprovalSignature(
      approval.id,
      signDigest(k.privateKey, hashPolicyApproval({ walletId: WALLET, ...input })),
    );
  }
  return approval;
}

function batchInput() {
  return {
    nonce: 0n,
    deadline: 9000n,
    calls: [
      { to: TO, value: 100n, data: new Uint8Array() },
      { to: newbie.address, value: 200n, data: new Uint8Array([1, 2, 3]) },
    ],
  };
}

function createBatchReady(wallet: MultiSigWallet, ownerActors: Actor[]) {
  const input = batchInput();
  const approval = wallet.createBatchApproval(input);
  
  for (const k of ownerActors.slice(0, 2)) {
    wallet.addBatchApprovalSignature(
      approval.id,
      signDigest(
        k.privateKey,
        hashBatchApproval({ walletId: WALLET, version: 1n, ...input }),
      ),
    );
  }
  return approval;
}

/** 对指定审批摘要生成撤销签名（默认 nonce 0、deadline 9000、当前钱包） */
function revokeSigs(
  ownerActors: Actor[],
  approvalDigest: string,
  overrides: { nonce?: bigint; deadline?: bigint; walletId?: string } = {},
) {
  return signApprovalRevocation(ownerActors.slice(0, 2), {
    walletId: overrides.walletId ?? WALLET,
    approvalDigest,
    nonce: overrides.nonce ?? 0n,
    deadline: overrides.deadline ?? 9000n,
  });
}

// ---------- 成功撤销（三类审批同构） ----------

test('撤销普通交易 ready 审批：返回 revoked 快照，只消费 nonce，不建任务/不改策略', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const before = {
    owners: wallet.currentOwners,
    confirmations: wallet.requiredConfirmations,
    version: wallet.policyVersion,
  };

  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  assert.equal(revoked.status, 'revoked');
  assert.equal(revoked.id, approval.id);
  assert.equal(revoked.digest, approval.digest);
  // 已收集签名者保留，但审批已失效
  assert.deepEqual(revoked.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);
  assert.ok(revoked.revocation);
  assert.equal(revoked.revocation!.nonce, 0n);
  assert.equal(revoked.revocation!.deadline, 9000n);
  assert.equal(revoked.revocation!.revokedAt, 1000n);

  // 撤销摘要 = safe-wallet/approval-revoke/v1（钱包标识、审批摘要、nonce、deadline）
  const expectedDigest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });
  assert.equal(revoked.revocation!.digest, expectedDigest.toString('hex'));

  // 只消费一次 nonce；不建任务、不改策略
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(0n), true);
  assert.equal(wallet.tasks.length, 0);
  assert.deepEqual(wallet.currentOwners, before.owners);
  assert.equal(wallet.requiredConfirmations, before.confirmations);
  assert.equal(wallet.policyVersion, before.version);

  // 查询仍是 revoked 终态
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'revoked');
});

test('撤销策略变更 ready 审批：revoked 终态 + 撤销记录，只消费 nonce', () => {
  const { wallet, ownerActors } = setup();
  const approval = createPolicyReady(wallet, ownerActors);

  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  assert.equal(revoked.status, 'revoked');
  assert.ok(revoked.revocation);
  assert.equal(wallet.getPolicyApproval(approval.id).status, 'revoked');
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, 1n);
  // 列表仍可见该审批（revoked）
  const listed = wallet.listPolicyApprovals();
  assert.equal(listed.length, 1);
  assert.equal(listed[0]!.status, 'revoked');
});

test('撤销批量交易 ready 审批：revoked 终态 + 撤销记录，只消费 nonce、calls 保留', () => {
  const { wallet, ownerActors } = setup();
  const approval = createBatchReady(wallet, ownerActors);

  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  assert.equal(revoked.status, 'revoked');
  assert.ok('calls' in revoked);
  if ('calls' in revoked) assert.equal(revoked.calls.length, 2);
  assert.ok(revoked.revocation);
  assert.equal(wallet.getBatchApproval(approval.id).status, 'revoked');
  assert.equal(wallet.listBatchApprovals()[0]!.status, 'revoked');
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 0);
});

test('collecting（签名尚未集齐）的审批也可撤销；撤销阈值与审批收集的签名互相独立', () => {
  const { wallet, ownerActors } = setup();
  // 只登记，不加任何审批签名
  const approval = wallet.createTransactionApproval(txInput());
  assert.equal(approval.status, 'collecting');

  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(revoked.status, 'revoked');
  assert.deepEqual(revoked.signers, []);
  assert.equal(wallet.expectedNonce, 1n);
});

test('撤销成功不产生回执：任务数为 0，且不影响后续 nonce 序列上的直接提交', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );
  assert.equal(wallet.tasks.length, 0);

  // nonce 序列继续推进：nonce 1 的直接提交正常入队
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 1n,
    deadline: 9000n,
    to: newbie.address,
    value: 5n,
  });
  const task = wallet.submitTransaction(
    { nonce: 1n, deadline: 9000n, to: newbie.address, value: 5n },
    txSigs,
  );
  assert.equal(task.nonce, 1n);
  assert.equal(wallet.expectedNonce, 2n);
});

// ---------- 校验顺序 1：字段 / 签名外形 ----------

test('字段畸形 → InvalidApprovalRevocationRequest，且不消费 nonce、不改审批', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const goodSigs = revokeSigs(ownerActors, approval.digest);

  const badRequest = (mutate: (r: Record<string, unknown>) => Record<string, unknown>, sigs = goodSigs) => {
    const base = { approvalId: approval.id, nonce: 0n, deadline: 9000n };
    assert.throws(
      () => wallet.revokeApproval(mutate({ ...base }) as never, sigs),
      InvalidApprovalRevocationRequest,
    );
  };

  badRequest((r) => ((r.approvalId = 123), r));
  badRequest((r) => ((r.approvalId = ''), r));
  badRequest((r) => ((r.approvalId = undefined), r));
  badRequest((r) => ((r.nonce = 'abc'), r));
  badRequest((r) => ((r.nonce = -1n), r));
  badRequest((r) => ((r.nonce = 2n ** 256n), r));
  badRequest((r) => ((r.deadline = 'xyz'), r));
  badRequest((r) => ((r.deadline = -1n), r));
  // null / 非对象请求
  assert.throws(() => wallet.revokeApproval(null as never, goodSigs), InvalidApprovalRevocationRequest);
  assert.throws(() => wallet.revokeApproval('id' as never, goodSigs), InvalidApprovalRevocationRequest);

  // 审批与 nonce 均未改变
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
});

test('签名集合畸形 → InvalidApprovalRevocationRequest', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const sub = { approvalId: approval.id, nonce: 0n, deadline: 9000n };
  const good = revokeSigs(ownerActors, approval.digest);

  assert.throws(() => wallet.revokeApproval(sub, [] as never), InvalidApprovalRevocationRequest);
  assert.throws(() => wallet.revokeApproval(sub, 'x' as never), InvalidApprovalRevocationRequest);
  assert.throws(() => wallet.revokeApproval(sub, undefined as never), InvalidApprovalRevocationRequest);
  assert.throws(
    () => wallet.revokeApproval(sub, [new Uint8Array(64), good[1]!] as never),
    InvalidApprovalRevocationRequest,
  );
  assert.throws(
    () => wallet.revokeApproval(sub, [new Uint8Array(66), good[1]!] as never),
    InvalidApprovalRevocationRequest,
  );
  assert.throws(
    () => wallet.revokeApproval(sub, [Buffer.from('nope'), good[1]!] as never),
    InvalidApprovalRevocationRequest,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

// ---------- 校验顺序 2/3/4：nonce 复用、过期、错序 ----------

test('nonce 已使用 → NonceAlreadyUsedError；重放恒得此异常（即使撤销 deadline 已过期）', () => {
  const { wallet, ownerActors, clock } = setup();
  const a1 = createTxReady(wallet, ownerActors);
  // 同 nonce 的另一候选必须在 nonce 被消费前登记（创建时仍校验 nonce 未用）
  const a2 = wallet.createTransactionApproval(txInput({ value: 88n }));

  const sigs1 = revokeSigs(ownerActors, a1.digest);
  wallet.revokeApproval({ approvalId: a1.id, nonce: 0n, deadline: 9000n }, sigs1);
  assert.equal(wallet.expectedNonce, 1n);

  // 同 nonce 重放（对另一未撤销审批）→ NonceAlreadyUsedError
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: a2.id, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, a2.digest),
      ),
    NonceAlreadyUsedError,
  );

  // 即使时钟走过 deadline（请求已过期），重放仍恒定为 NonceAlreadyUsedError
  clock.set(20000n);
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: a2.id, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, a2.digest, { deadline: 9000n }),
      ),
    NonceAlreadyUsedError,
  );
});

test('deadline 早于当前时间 → RequestExpired（不消费 nonce、不撤销）', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: 999n },
        revokeSigs(ownerActors, approval.digest, { deadline: 999n }),
      ),
    RequestExpired,
  );
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');
  assert.equal(wallet.expectedNonce, 0n);
});

test('deadline 恰好等于当前时间：边界有效（“早于”才过期）', () => {
  const { wallet, ownerActors } = setup(); // now = 1000
  const approval = createTxReady(wallet, ownerActors);
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 1000n },
    revokeSigs(ownerActors, approval.digest, { deadline: 1000n }),
  );
  assert.equal(revoked.status, 'revoked');
});

test('nonce 未使用但错序 → InvalidApprovalRevocationNonceError（过期优先于错序）', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);

  // nonce 错序（跳号）
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 1n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
      ),
    InvalidApprovalRevocationNonceError,
  );
  // 过期 + 错序：过期（第 3 步）优先于错序（第 4 步）
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 5n, deadline: 500n },
        revokeSigs(ownerActors, approval.digest, { nonce: 5n, deadline: 500n }),
      ),
    RequestExpired,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

// ---------- 校验顺序 5/6：存在性、状态 ----------

test('审批不存在 → ApprovalNotFoundError（错序优先于不存在；不存在优先于签名问题）', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);

  // 不存在的 id + 合法 nonce/deadline/签名外形 → ApprovalNotFoundError
  const missing = 'deadbeefdeadbeef';
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: missing, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest),
      ),
    ApprovalNotFoundError,
  );

  // 错序（第 4 步）优先于不存在（第 5 步）
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: missing, nonce: 5n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest, { nonce: 5n }),
      ),
    InvalidApprovalRevocationNonceError,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('已提交（submitted）审批不可撤销 → ApprovalRevocationConflictError', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  // 提交审批：消费 nonce 0，审批进入 submitted
  wallet.submitApprovedTransaction(approval.id);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'submitted');

  // 撤销需用下一个 nonce 1；状态冲突（第 6 步）先于签名内容（第 7 步）
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 1n, deadline: 9000n },
        // 故意签错摘要，验证状态冲突优先
        revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
      ),
    ApprovalRevocationConflictError,
  );
  // 已提交终态不改变，任务仍在
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'submitted');
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.expectedNonce, 1n);
});

test('已撤销审批再撤销 → ApprovalRevocationConflictError；只消费一次 nonce', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 1n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
      ),
    ApprovalRevocationConflictError,
  );
  // 失败不消费 nonce
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(1n), false);
});

// ---------- 校验顺序 7：签名 ----------

test('签名与撤销摘要不匹配（改绑其他审批摘要）→ InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const target = createTxReady(wallet, ownerActors);
  const other = wallet.createTransactionApproval(txInput({ value: 99n }));

  // 用 other 的审批摘要生成撤销签名，拿去撤销 target
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: target.id, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, other.digest),
      ),
    InvalidApprovalRevocationSigner,
  );
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.getTransactionApproval(target.id).status, 'ready');
});

test('跨钱包签名无效 → InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest, { walletId: OTHER_WALLET }),
      ),
    InvalidApprovalRevocationSigner,
  );
});

test('签名者非当前所有者（newbie / 已被移除的旧 owner）→ InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);

  const digest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });
  // newbie + 一个真 owner：非所有者签名直接报错（先于阈值判定）
  const sigs = [signDigest(newbie.privateKey, digest), signDigest(ownerActors[0]!.privateKey, digest)];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, sigs),
    InvalidApprovalRevocationSigner,
  );
});

test('去重签名不足当前确认数 → ApprovalRevocationThresholdNotMetError', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const digest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });

  // 只有一个所有者签名
  const one = [signDigest(ownerActors[0]!.privateKey, digest)];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, one),
    ApprovalRevocationThresholdNotMetError,
  );

  // 同一所有者签名重复两次：去重后仍只有 1 个
  const dup = [signDigest(ownerActors[0]!.privateKey, digest), signDigest(ownerActors[0]!.privateKey, digest)];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, dup),
    ApprovalRevocationThresholdNotMetError,
  );
  assert.equal(wallet.expectedNonce, 0n);
});

test('签名者错误优先于阈值不足；阈值恰好满足（含重复签名去重）即可撤销', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const digest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });

  // [newbie, newbie]：第一个签名即非所有者 → signer 错误，而非 threshold
  const bad = [signDigest(newbie.privateKey, digest), signDigest(newbie.privateKey, digest)];
  assert.throws(
    () => wallet.revokeApproval({ approvalId: approval.id, nonce: 0n, deadline: 9000n }, bad),
    InvalidApprovalRevocationSigner,
  );

  // 两个真 owner + 其中一个重复：去重后 2 个，达到阈值
  const enough = [
    signDigest(ownerActors[0]!.privateKey, digest),
    signDigest(ownerActors[1]!.privateKey, digest),
    signDigest(ownerActors[0]!.privateKey, digest),
  ];
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    enough,
  );
  assert.equal(revoked.status, 'revoked');
});

// ---------- 跨操作签名互不通用 ----------

test('其他操作（交易/审批加签/取消）的签名不能用于撤销', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const sub = { approvalId: approval.id, nonce: 0n, deadline: 9000n };

  // 普通交易直接提交签名（safe-wallet/tx/v1）
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  assert.throws(() => wallet.revokeApproval(sub, txSigs), InvalidApprovalRevocationSigner);

  // 审批加签签名（safe-wallet/tx-approval/v1）
  const approvalSigs = signTransactionApproval(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  assert.throws(() => wallet.revokeApproval(sub, approvalSigs), InvalidApprovalRevocationSigner);

  // 任务取消签名（safe-wallet/cancel/v1）
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });
  assert.throws(() => wallet.revokeApproval(sub, cancelSigs), InvalidApprovalRevocationSigner);

  assert.equal(wallet.expectedNonce, 0n);
});

test('撤销签名不能用于普通交易直接提交（域分隔反向验证）', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const revoke = revokeSigs(ownerActors, approval.digest);
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 0n, deadline: 9000n, to: TO, value: 7n },
        revoke,
      ),
    /InvalidTransaction/,
  );
});

// ---------- expired / conflicted 仍可撤销，revoked 优先级最高 ----------

test('已过期（expired）审批仍可撤销；撤销请求有独立 deadline；revoked 优先于 expired', () => {
  const { wallet, ownerActors, clock } = setup();
  const approval = createTxReady(wallet, ownerActors);
  clock.set(9001n); // 审批 deadline 9000 已过
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'expired');

  // 过期审批：加签 / 提交仍按原规则拒绝
  assert.throws(
    () => wallet.addApprovalSignature(approval.id, new Uint8Array(65)),
    ApprovalExpiredError,
  );

  // 撤销请求自身 deadline 为未来时间 → 可撤销
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 20000n },
    revokeSigs(ownerActors, approval.digest, { deadline: 20000n }),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'revoked');

  // 时钟再走，状态仍是 revoked（revoked 优先于 expired）
  clock.set(50000n);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'revoked');
});

test('版本漂移（conflicted）审批仍可撤销；撤销按当前所有者验签，revoked 优先于 conflicted', () => {
  const { wallet, ownerActors, clock } = setup();
  // 审批 A 待撤销（绑定 nonce 0 / version 1）
  const approval = createPolicyReady(wallet, ownerActors);

  // 直接提交并执行一次策略变更（nonce 0，版本 1 → 2），所有者不变
  
  const pcDigest = hashPolicyChange({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners: addresses(ownerActors),
    newConfirmations: 2n,
  });
  const pcSigs = ownerActors.slice(0, 2).map((k) => signDigest(k.privateKey, pcDigest));
  const task = wallet.proposePolicyChange(
    {
      version: 1n,
      nonce: 0n,
      deadline: 9000n,
      newOwners: addresses(ownerActors),
      newConfirmations: 2n,
    },
    pcSigs,
  );
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.getPolicyApproval(approval.id).status, 'conflicted');

  // conflicted：加签/提交仍抛 ApprovalPolicyConflictError
  assert.throws(
    () => wallet.addPolicyApprovalSignature(approval.id, new Uint8Array(65)),
    ApprovalPolicyConflictError,
  );

  // 撤销用新 nonce 1（当前所有者签名）→ 成功，状态为 revoked 而非 conflicted
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: 20000n },
    revokeSigs(ownerActors, approval.digest, { nonce: 1n, deadline: 20000n }),
  );
  assert.equal(revoked.status, 'revoked');
  clock.set(50000n);
  assert.equal(wallet.getPolicyApproval(approval.id).status, 'revoked');
  assert.equal(wallet.policyVersion, 2n);
});

test('版本漂移后旧所有者（已不在 owners 中）的撤销签名 → InvalidApprovalRevocationSigner', () => {
  const { wallet, ownerActors } = setup();
  const approval = createPolicyReady(wallet, ownerActors);

  // 策略变更：所有者换成 [owner0, newbie, newbie2]
  const newbie2 = generateKeyPair();
  const newOwners = [ownerActors[0]!.address, newbie.address, newbie2.address];
  
  const pcDigest = hashPolicyChange({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    newOwners,
    newConfirmations: 1n,
  });
  const pcSigs = ownerActors.slice(0, 2).map((k) => signDigest(k.privateKey, pcDigest));
  const task = wallet.proposePolicyChange(
    { version: 1n, nonce: 0n, deadline: 9000n, newOwners, newConfirmations: 1n },
    pcSigs,
  );
  wallet.executeTask(task.id);

  // owner1 已不是所有者：其撤销签名被拒
  const revokeDigest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 1n,
    deadline: 9000n,
  });
  const staleSigs = [signDigest(ownerActors[1]!.privateKey, revokeDigest)];
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 1n, deadline: 9000n },
        staleSigs,
      ),
    InvalidApprovalRevocationSigner,
  );
});

// ---------- revoked 之后的行为 ----------

test('revoked 后加签、提交、再撤销一律抛 ApprovalRevocationConflictError', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );

  const digest = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  assert.throws(
    () => wallet.addApprovalSignature(approval.id, signDigest(ownerActors[2]!.privateKey, digest)),
    ApprovalRevocationConflictError,
  );
  assert.throws(
    () => wallet.submitApprovedTransaction(approval.id),
    ApprovalRevocationConflictError,
  );
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 1n, deadline: 9000n },
        revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
      ),
    ApprovalRevocationConflictError,
  );
});

test('revoked 快照保留签名者与撤销记录，且不受之后时钟/版本漂移影响', () => {
  const { wallet, ownerActors, clock } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest),
  );
  assert.deepEqual(revoked.signers, [ownerActors[0]!.address, ownerActors[1]!.address]);
  assert.equal(revoked.revocation!.digest.length, 64);

  clock.set(40000n); // 审批 deadline 早已过
  const snap = wallet.getTransactionApproval(approval.id);
  assert.equal(snap.status, 'revoked');
  assert.equal(snap.revocation!.digest, revoked.revocation!.digest);
  assert.deepEqual(snap.signers, revoked.signers);
});

// ---------- 未撤销审批与既有行为不变 ----------

test('撤销一个候选审批不影响其他未撤销审批：另一审批仍可加签/查询（同 nonce 候选）', () => {
  const { wallet, ownerActors } = setup();
  const a = createTxReady(wallet, ownerActors);
  // 同 nonce 的另一候选（内容不同），只登记
  const b = wallet.createTransactionApproval(txInput({ value: 88n }));

  wallet.revokeApproval(
    { approvalId: a.id, nonce: 0n, deadline: 9000n },
    revokeSigs(ownerActors, a.digest),
  );

  // b 仍可加签（加签不看 nonce）
  const bDigest = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 88n,
    data: new Uint8Array(),
  });
  wallet.addApprovalSignature(b.id, signDigest(ownerActors[0]!.privateKey, bDigest));
  wallet.addApprovalSignature(b.id, signDigest(ownerActors[1]!.privateKey, bDigest));
  assert.equal(wallet.getTransactionApproval(b.id).status, 'ready');

  // b 提交时 nonce 0 已被撤销消费 → 既有 NonceAlreadyUsedError 语义不变
  assert.throws(() => wallet.submitApprovedTransaction(b.id), NonceAlreadyUsedError);
});

test('撤销失败不消费 nonce、不改审批/策略/任务（threshold 不足场景）', () => {
  const { wallet, ownerActors } = setup();
  const approval = createTxReady(wallet, ownerActors);
  const digest = hashApprovalRevocation({
    walletId: WALLET,
    approvalDigest: approval.digest,
    nonce: 0n,
    deadline: 9000n,
  });
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: 9000n },
        [signDigest(ownerActors[0]!.privateKey, digest)],
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.isNonceUsed(0n), false);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.tasks.length, 0);

  // 失败后可用同 nonce 重新发起并成功
  const ok = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: 9000n },
    [signDigest(ownerActors[0]!.privateKey, digest), signDigest(ownerActors[1]!.privateKey, digest)],
  );
  assert.equal(ok.status, 'revoked');
});

test('撤销后既有已提交任务的执行 / 幂等 / cancelTask 行为不变', () => {
  const { wallet, ownerActors } = setup();
  // 先登记审批（绑定 nonce 0，不消费），再用 nonce 0 提交一个普通交易任务
  const approval = wallet.createTransactionApproval(txInput());
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  const task = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: TO, value: 7n },
    txSigs,
  );

  // 撤销请求使用自己的下一个期望 nonce 1（与审批绑定的创建 nonce 0 相互独立）
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
  );
  assert.equal(revoked.status, 'revoked');

  // 任务执行不受影响
  const done = wallet.executeTask(task.id);
  assert.equal(done.status, 'executed');
  assert.equal((done.receipt!.result as { kind: string }).kind, 'transfer');
  // 终态幂等
  const again = wallet.executeTask(task.id);
  assert.equal(again.status, 'executed');
  assert.equal(again.receipt, done.receipt);
});

test('撤销对已入队 queued 任务无影响：另一任务仍可被 cancelTask 正常取消', () => {
  const { wallet, ownerActors } = setup();
  // 先登记审批（绑定 nonce 0，不消费），再用 nonce 0 提交普通交易任务
  const approval = wallet.createTransactionApproval(txInput());
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
  });
  const task = wallet.submitTransaction(
    { nonce: 0n, deadline: 9000n, to: TO, value: 7n },
    txSigs,
  );

  // nonce 1 撤销与任务无关的登记审批
  wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: 9000n },
    revokeSigs(ownerActors, approval.digest, { nonce: 1n }),
  );

  // nonce 2 取消该 queued 任务
  const cancelSigs = signCancellation(ownerActors.slice(0, 2), {
    walletId: WALLET,
    taskDigest: task.digest,
    nonce: 2n,
    deadline: 9000n,
  });
  const cancelled = wallet.cancelTask(task.id, 2n, 9000n, cancelSigs);
  assert.equal(cancelled.status, 'cancelled');
  assert.ok(cancelled.cancellation);
  assert.equal(wallet.expectedNonce, 3n);
});

// ---------- 摘要域分隔 ----------

test('hashApprovalRevocation：域标签 / 钱包 / 审批摘要 / nonce / deadline 任一变化都改变摘要', () => {
  const base = {
    walletId: WALLET,
    approvalDigest: 'ab'.repeat(32),
    nonce: 0n,
    deadline: 9000n,
  };
  const d0 = hashApprovalRevocation(base);
  assert.notDeepEqual(
    d0,
    hashApprovalRevocation({ ...base, walletId: OTHER_WALLET }),
  );
  assert.notDeepEqual(
    d0,
    hashApprovalRevocation({ ...base, approvalDigest: 'cd'.repeat(32) }),
  );
  assert.notDeepEqual(d0, hashApprovalRevocation({ ...base, nonce: 1n }));
  assert.notDeepEqual(d0, hashApprovalRevocation({ ...base, deadline: 9001n }));
  // 与审批摘要 / 交易摘要均不同
  const approvalDigest = hashTransactionApproval({
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  const txDigest = hashTransaction({
    walletId: WALLET,
    nonce: 0n,
    deadline: 9000n,
    to: TO,
    value: 7n,
    data: new Uint8Array(),
  });
  assert.notEqual(d0.toString('hex'), approvalDigest.toString('hex'));
  assert.notEqual(d0.toString('hex'), txDigest.toString('hex'));
});
