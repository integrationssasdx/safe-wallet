import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet, MAX_BATCH_CALLS, type ValueThreshold } from '../src/wallet.ts';
import {
  ApprovalRevocationThresholdNotMetError,
  ApprovalThresholdNotMetError,
  InvalidCancellation,
  InvalidPolicyChange,
  InvalidQueueStateError,
  InvalidSpendingPolicy,
  InvalidSpendingValueError,
  InvalidTransaction,
  InvalidTransactionBatch,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
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
  type Actor,
} from './helpers.ts';
import { generateKeyPair, signDigest } from '../src/crypto.ts';
import {
  hashApprovalRevocation,
  hashBatchApproval,
  hashPolicyApproval,
  hashPolicyChange,
  hashTransaction,
  hashTransactionApproval,
  hashTransactionBatch,
} from '../src/encoding.ts';

const WALLET = 'wallet-tiered';
const DEADLINE = 9000n;

// 4 所有者、全局 1 签；1_000 起 2 签、10_000 起 3 签、50_000 起 4 签
const TIERS: ValueThreshold[] = [
  { minimumValue: 1_000n, confirmations: 2n },
  { minimumValue: 10_000n, confirmations: 3n },
  { minimumValue: 50_000n, confirmations: 4n },
];

const recipient = () => generateKeyPair().address;

function tieredWallet(
  ownerCount = 4,
  confirmations = 1n,
  valueThresholds: readonly ValueThreshold[] | undefined = TIERS,
) {
  const ownerActors = actors(ownerCount);
  const clock = fakeClock(1000n);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations,
    valueThresholds,
    now: clock.now,
  });
  return { ownerActors, clock, wallet };
}

/** 无规则（无档位）孪生钱包：用于比对 digest / 载荷不随档位改变 */
function twinWallet(ownerActors: Actor[], confirmations: bigint, withTiers: boolean) {
  return new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations,
    valueThresholds: withTiers ? TIERS : undefined,
    now: () => 1000n,
  });
}

const txSigs = (
  ownerActors: Actor[],
  who: readonly number[],
  fields: { nonce?: bigint; deadline?: bigint; to: string; value: bigint; data?: Uint8Array },
) =>
  signTransaction(
    who.map((i) => ownerActors[i]!),
    {
      walletId: WALLET,
      nonce: fields.nonce ?? 0n,
      deadline: fields.deadline ?? DEADLINE,
      to: fields.to,
      value: fields.value,
      data: fields.data ?? new Uint8Array(),
    },
  );

const batchSigs = (
  ownerActors: Actor[],
  who: readonly number[],
  calls: { to: string; value: bigint; data: Uint8Array }[],
  nonce = 0n,
) =>
  signBatchTransaction(
    who.map((i) => ownerActors[i]!),
    { walletId: WALLET, nonce, deadline: DEADLINE, calls },
  );

const calls = (spec: [bigint, bigint?][]): { to: string; value: bigint; data: Uint8Array }[] =>
  spec.map(([value]) => ({ to: recipient(), value, data: new Uint8Array() }));

// ============================================================
// 构造期校验
// ============================================================

test('构造：缺省 valueThresholds 与空数组都是无规则钱包', () => {
  const a = actors(3);
  const w1 = new MultiSigWallet({ id: 'w', owners: addresses(a), confirmations: 2n });
  const w2 = new MultiSigWallet({ id: 'w', owners: addresses(a), confirmations: 2n, valueThresholds: [] });
  assert.deepEqual(w1.spendingThresholds, []);
  assert.deepEqual(w2.spendingThresholds, []);
  assert.equal(w1.maxSpendingConfirmations, 2n);
  assert.equal(w2.maxSpendingConfirmations, 2n);
  assert.equal(w1.requiredConfirmationsForValue(10n ** 30n), 2n);
});

test('构造：合法档位（含持平确认数、单档、2^256-1 边界）', () => {
  const a = actors(4);
  const w = new MultiSigWallet({
    id: 'w',
    owners: addresses(a),
    confirmations: 1n,
    valueThresholds: [
      { minimumValue: 1n, confirmations: 2n },
      { minimumValue: 1_000n, confirmations: 2n }, // 持平允许
      { minimumValue: 2n ** 256n - 1n, confirmations: 4n },
    ],
  });
  assert.equal(w.requiredConfirmationsForValue(2n ** 256n - 1n), 4n);
  assert.deepEqual(w.spendingThresholds, [
    { minimumValue: 1n, confirmations: 2n },
    { minimumValue: 1_000n, confirmations: 2n },
    { minimumValue: 2n ** 256n - 1n, confirmations: 4n },
  ]);
});

test('构造：minimumValue 越界（0 / 2^256 / 负数 / 非整数）→ InvalidSpendingPolicy', () => {
  const a = actors(3);
  const make = (valueThresholds: unknown) =>
    () =>
      new MultiSigWallet({
        id: 'w',
        owners: addresses(a),
        confirmations: 1n,
        valueThresholds: valueThresholds as ValueThreshold[],
      });
  for (const bad of [0n, 2n ** 256n, -1n, 'abc', undefined, 1.5, Number.NaN, {}]) {
    assert.throws(make([{ minimumValue: bad, confirmations: 2n }]), InvalidSpendingPolicy);
  }
});

test('构造：minimumValue 不严格递增（相等 / 逆序）→ InvalidSpendingPolicy', () => {
  const a = actors(3);
  const make = (valueThresholds: ValueThreshold[]) =>
    () => new MultiSigWallet({ id: 'w', owners: addresses(a), confirmations: 1n, valueThresholds });
  assert.throws(
    make([
      { minimumValue: 1_000n, confirmations: 2n },
      { minimumValue: 1_000n, confirmations: 3n },
    ]),
    InvalidSpendingPolicy,
  );
  assert.throws(
    make([
      { minimumValue: 2_000n, confirmations: 2n },
      { minimumValue: 1_000n, confirmations: 3n },
    ]),
    InvalidSpendingPolicy,
  );
});

test('构造：confirmations 非法（0 / 负 / 低于全局 / 高于所有者数 / 下降 / 非整数）→ InvalidSpendingPolicy', () => {
  const a = actors(3);
  const make = (confirmations: bigint, valueThresholds: ValueThreshold[]) =>
    () => new MultiSigWallet({ id: 'w', owners: addresses(a), confirmations, valueThresholds });
  assert.throws(make(1n, [{ minimumValue: 1n, confirmations: 0n }]), InvalidSpendingPolicy);
  assert.throws(make(1n, [{ minimumValue: 1n, confirmations: -1n }]), InvalidSpendingPolicy);
  assert.throws(make(2n, [{ minimumValue: 1n, confirmations: 1n }]), InvalidSpendingPolicy);
  assert.throws(make(1n, [{ minimumValue: 1n, confirmations: 4n }]), InvalidSpendingPolicy);
  assert.throws(
    make(1n, [
      { minimumValue: 1n, confirmations: 3n },
      { minimumValue: 2n, confirmations: 2n },
    ]),
    InvalidSpendingPolicy,
  );
  assert.throws(
    make(1n, [{ minimumValue: 1n, confirmations: 'x' as unknown as bigint }]),
    InvalidSpendingPolicy,
  );
});

test('构造：档位表形状非法（非数组 / 项非对象 / null）→ InvalidSpendingPolicy 且无实例', () => {
  const a = actors(3);
  for (const bad of ['x', 42, null, [null], ['x'], [42], [[]]]) {
    assert.throws(
      () =>
        new MultiSigWallet({
          id: 'w',
          owners: addresses(a),
          confirmations: 1n,
          valueThresholds: bad as unknown as ValueThreshold[],
        }),
      InvalidSpendingPolicy,
    );
  }
});

test('构造：档位字段接受安全整数与纯数字字符串（安全标量转换）', () => {
  const a = actors(3);
  const w = new MultiSigWallet({
    id: 'w',
    owners: addresses(a),
    confirmations: 1,
    valueThresholds: [
      { minimumValue: 1000, confirmations: 2 },
      // 运行时安全标量转换同样接受纯数字字符串（公开类型仍为 bigint | number，与既有提交口径一致）
      { minimumValue: '10000', confirmations: '3' },
    ] as ValueThreshold[],
  });
  assert.equal(w.requiredConfirmationsForValue(999n), 1n);
  assert.equal(w.requiredConfirmationsForValue(1000n), 2n);
  assert.equal(w.requiredConfirmationsForValue(10000n), 3n);
});

test('构造：档位快照是副本，外部或返回值改动不影响引擎', () => {
  const a = actors(3);
  const tiers = [{ minimumValue: 1n, confirmations: 2n }];
  const w = new MultiSigWallet({ id: 'w', owners: addresses(a), confirmations: 1n, valueThresholds: tiers });
  tiers[0]!.minimumValue = 999n; // 构造后外部篡改原数组不生效
  assert.deepEqual(w.spendingThresholds, [{ minimumValue: 1n, confirmations: 2n }]);
  const snapshot = w.spendingThresholds;
  (snapshot as { minimumValue: bigint }[])[0]!.minimumValue = 5n;
  assert.equal(w.requiredConfirmationsForValue(1n), 2n);
});

// ============================================================
// 只读取档
// ============================================================

test('requiredConfirmationsForValue：取不超过 value 的最高档，未命中回落全局', () => {
  const { wallet } = tieredWallet();
  assert.equal(wallet.requiredConfirmationsForValue(0n), 1n);
  assert.equal(wallet.requiredConfirmationsForValue(999n), 1n);
  assert.equal(wallet.requiredConfirmationsForValue(1_000n), 2n); // 边界含 minimumValue
  assert.equal(wallet.requiredConfirmationsForValue(9_999n), 2n);
  assert.equal(wallet.requiredConfirmationsForValue(10_000n), 3n);
  assert.equal(wallet.requiredConfirmationsForValue(49_999n), 3n);
  assert.equal(wallet.requiredConfirmationsForValue(50_000n), 4n);
  assert.equal(wallet.requiredConfirmationsForValue(10n ** 30n), 4n);
  // 接受安全整数与纯数字字符串
  assert.equal(wallet.requiredConfirmationsForValue(10_000), 3n);
  assert.equal(wallet.requiredConfirmationsForValue('1000'), 2n);
});

test('requiredConfirmationsForValue：负数 / 超 256 位 / 不可解析 → InvalidSpendingValueError', () => {
  const { wallet } = tieredWallet();
  for (const bad of [-1n, 2n ** 256n, 2n ** 300n, -5, -1.5, 'abc', 1.5, null, undefined, {}]) {
    assert.throws(
      () => wallet.requiredConfirmationsForValue(bad as bigint),
      InvalidSpendingValueError,
    );
  }
});

test('requiredConfirmationsForBatch：校验 calls 并按总额取档', () => {
  const { wallet } = tieredWallet();
  // 两笔各 600（单笔都未命中 1_000 档），总额 1_200 → 2 签
  assert.equal(
    wallet.requiredConfirmationsForBatch(calls([[600n], [600n]])),
    2n,
  );
  // 总额边界 10_000 → 3 签；总额 51_000 → 4 签
  assert.equal(wallet.requiredConfirmationsForBatch(calls([[4_000n], [6_000n]])), 3n);
  assert.equal(wallet.requiredConfirmationsForBatch(calls([[25_000n], [26_000n]])), 4n);
});

test('requiredConfirmationsForBatch：空批量 / 非法项 → InvalidTransactionBatch', () => {
  const { wallet } = tieredWallet();
  assert.throws(() => wallet.requiredConfirmationsForBatch([]), InvalidTransactionBatch);
  assert.throws(
    () => wallet.requiredConfirmationsForBatch([{ to: recipient(), value: 1n }] as never),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.requiredConfirmationsForBatch(calls([[-1n]])),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.requiredConfirmationsForBatch(calls([[2n ** 256n]])),
    InvalidTransactionBatch,
  );
  assert.throws(
    () =>
      wallet.requiredConfirmationsForBatch([
        { to: '0xnot-an-address', value: 1n, data: new Uint8Array() },
      ]),
    InvalidTransactionBatch,
  );
  assert.throws(
    () => wallet.requiredConfirmationsForBatch(calls(Array(MAX_BATCH_CALLS + 1).fill([1n]))),
    InvalidTransactionBatch,
  );
});

test('查询不消费 nonce、不建任务、不改状态', () => {
  const { wallet } = tieredWallet();
  for (let i = 0; i < 5; i++) {
    wallet.requiredConfirmationsForValue(10_000n);
    wallet.requiredConfirmationsForBatch(calls([[4_000n], [7_000n]]));
    wallet.spendingThresholds;
    wallet.maxSpendingConfirmations;
  }
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 1n);
});

// ============================================================
// 直接提交：单笔按金额
// ============================================================

test('直接单笔：各档所需签名数；不足 → InvalidTransaction 且无任何副作用', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();

  // 500 → 1 签即可
  assert.doesNotThrow(() =>
    wallet.submitTransaction(
      { nonce: 0n, deadline: DEADLINE, to, value: 500n },
      txSigs(ownerActors, [0], { to, value: 500n }),
    ),
  );

  // 1_000 → 需 2 签；1 签被拒
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 1n, deadline: DEADLINE, to, value: 1_000n },
        txSigs(ownerActors, [0], { nonce: 1n, to, value: 1_000n }),
      ),
    InvalidTransaction,
  );
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 1); // 只有前一笔成功入队
  assert.doesNotThrow(() =>
    wallet.submitTransaction(
      { nonce: 1n, deadline: DEADLINE, to, value: 1_000n },
      txSigs(ownerActors, [0, 1], { nonce: 1n, to, value: 1_000n }),
    ),
  );

  // 10_000 → 需 3 签；2 签被拒
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 2n, deadline: DEADLINE, to, value: 10_000n },
        txSigs(ownerActors, [0, 1], { nonce: 2n, to, value: 10_000n }),
      ),
    InvalidTransaction,
  );
  assert.equal(wallet.expectedNonce, 2n);

  // 50_000 → 需 4 签；3 签被拒，4 签成功
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 2n, deadline: DEADLINE, to, value: 50_000n },
        txSigs(ownerActors, [0, 1, 2], { nonce: 2n, to, value: 50_000n }),
      ),
    InvalidTransaction,
  );
  assert.doesNotThrow(() =>
    wallet.submitTransaction(
      { nonce: 2n, deadline: DEADLINE, to, value: 50_000n },
      txSigs(ownerActors, [0, 1, 2, 3], { nonce: 2n, to, value: 50_000n }),
    ),
  );
  assert.equal(wallet.expectedNonce, 3n);
  assert.equal(wallet.tasks.length, 3);
});

test('直接单笔：负数 / 超 256 位金额仍抛 InvalidTransaction（查询错误不外泄到提交路径）', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  for (const value of [-1n, 2n ** 256n]) {
    assert.throws(
      () =>
        wallet.submitTransaction(
          { nonce: 0n, deadline: DEADLINE, to, value },
          txSigs(ownerActors, [0, 1, 2, 3], { to, value: 0n }),
        ),
      InvalidTransaction,
    );
  }
  assert.equal(wallet.expectedNonce, 0n);
});

test('直接单笔：错误优先级不变（nonce 复用 → 过期 → 阈值）', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  // 先用 nonce 0 成功一笔
  wallet.submitTransaction(
    { nonce: 0n, deadline: DEADLINE, to, value: 500n },
    txSigs(ownerActors, [0], { to, value: 500n }),
  );
  // 高档金额 + 只 1 签 + nonce 复用 → 恒为 NonceAlreadyUsedError
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 0n, deadline: DEADLINE, to, value: 50_000n },
        txSigs(ownerActors, [0], { to, value: 50_000n }),
      ),
    NonceAlreadyUsedError,
  );
  // 高档金额 + 只 1 签 + 已过期 → RequestExpired 优先于阈值
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 1n, deadline: 500n, to, value: 50_000n },
        txSigs(ownerActors, [0], { nonce: 1n, deadline: 500n, to, value: 50_000n }),
      ),
    RequestExpired,
  );
});

test('直接单笔：档位不进签名载荷——与无规则孪生钱包 digest/payload 完全一致', () => {
  const a = actors(4);
  const wTiers = twinWallet(a, 1n, true);
  const wPlain = twinWallet(a, 1n, false);
  const to = recipient();
  const fields = { nonce: 0n, deadline: DEADLINE, to, value: 10_000n, data: new Uint8Array() };
  const sigs = txSigs(a, [0, 1, 2], fields);
  const t1 = wTiers.submitTransaction(fields, sigs);
  const t2 = wPlain.submitTransaction(fields, sigs);
  assert.equal(t1.digest, t2.digest);
  assert.equal(
    t1.digest,
    hashTransaction({ walletId: WALLET, ...fields }).toString('hex'),
  );
  assert.deepEqual(t1.payload, t2.payload);
  // 执行回执也一致
  assert.deepEqual(wTiers.executeTask(t1.id).receipt?.result, wPlain.executeTask(t2.id).receipt?.result);
});

// ============================================================
// 直接提交：批量按总额
// ============================================================

test('直接批量：按 calls 总额取档；不足 → InvalidTransactionBatch 且无副作用', () => {
  const { wallet, ownerActors } = tieredWallet();
  const low = calls([[600n], [600n]]); // 总额 1_200 → 2 签
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 0n, deadline: DEADLINE, calls: low }, batchSigs(ownerActors, [0], low)),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
  const task = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: DEADLINE, calls: low },
    batchSigs(ownerActors, [0, 1], low),
  );

  // 总额 51_000 → 4 签；3 签被拒
  const high = calls([[25_000n], [26_000n]]);
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 1n, deadline: DEADLINE, calls: high }, batchSigs(ownerActors, [0, 1, 2], high, 1n)),
    InvalidTransactionBatch,
  );
  assert.equal(wallet.expectedNonce, 1n);
  wallet.submitBatchTransaction(
    { nonce: 1n, deadline: DEADLINE, calls: high },
    batchSigs(ownerActors, [0, 1, 2, 3], high, 1n),
  );

  // 摘要与回执形状不变；执行只产一个 transfer-batch 回执
  assert.equal(
    task.digest,
    hashTransactionBatch({ walletId: WALLET, nonce: 0n, deadline: DEADLINE, calls: low }).toString('hex'),
  );
  const done = wallet.executeTask(task.id);
  assert.equal((done.receipt!.result as { kind: string }).kind, 'transfer-batch');
});

// ============================================================
// 策略变更：恒按最大档；新所有者数低于最大档拒绝
// ============================================================

test('直接策略变更：恒需最大档签名；新所有者数低于最大档 → InvalidPolicyChange', () => {
  const { wallet, ownerActors } = tieredWallet(); // max = 4
  const newbie = generateKeyPair();
  const base = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };

  // 3 签（超过全局 1、达到中档，但不足最大档 4）→ InvalidPolicyChange
  assert.throws(
    () =>
      wallet.proposePolicyChange(base, signPolicyChange(ownerActors.slice(0, 3), { walletId: WALLET, ...base })),
    InvalidPolicyChange,
  );
  assert.equal(wallet.expectedNonce, 0n);

  // 新所有者只有 3 人（即使新确认数只要 1、且凑齐 4 个当前所有者签名）→ InvalidPolicyChange
  const shrink = { ...base, newOwners: [ownerActors[0]!.address, ownerActors[1]!.address, newbie.address] };
  assert.throws(
    () =>
      wallet.proposePolicyChange(shrink, signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...shrink })),
    InvalidPolicyChange,
  );
  assert.equal(wallet.expectedNonce, 0n);

  // 4 签且新所有者 4 人 → 入队；执行成功
  const task = wallet.proposePolicyChange(
    base,
    signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...base }),
  );
  wallet.executeTask(task.id);
  assert.equal(wallet.policyVersion, 2n);
  assert.equal(wallet.requiredConfirmations, 1n);
  // 档位表是静态的：最大档仍是 4
  assert.equal(wallet.maxSpendingConfirmations, 4n);
});

test('档位静态：全局确认数下调后，命中档位仍按静态档，未命中回落新全局值', () => {
  const { wallet, ownerActors } = tieredWallet();
  // 策略变更：仍 4 名所有者，全局确认数 1 → 1（实际改为同一集合，验证阈值取值）
  const base = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const task = wallet.proposePolicyChange(
    base,
    signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...base }),
  );
  wallet.executeTask(task.id);

  assert.equal(wallet.requiredConfirmationsForValue(500n), 1n); // 未命中 → 当前全局
  assert.equal(wallet.requiredConfirmationsForValue(1_000n), 2n); // 命中 → 静态档不随全局下降
  assert.equal(wallet.requiredConfirmationsForValue(50_000n), 4n);
  // 想缩编到 3 名所有者仍被最大档拦截
  const shrink = {
    ...base,
    version: 2n,
    nonce: 1n,
    newOwners: addresses(ownerActors).slice(0, 3),
  };
  assert.throws(
    () =>
      wallet.proposePolicyChange(shrink, signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...shrink })),
    InvalidPolicyChange,
  );
});

test('无规则钱包：所有者数低于旧全局确认数的原子缩编仍允许（旧行为不回归）', () => {
  // 3 所有者 / 2 签 → 1 所有者 / 1 签：基线规则只要求 newConfirmations <= newOwners
  const ownerActors = actors(3);
  const wallet = new MultiSigWallet({
    id: 'plain',
    owners: addresses(ownerActors),
    confirmations: 2n,
    now: () => 1000n,
  });
  const newbie = generateKeyPair();
  const sub = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: [newbie.address],
    newConfirmations: 1n,
  };
  const task = wallet.proposePolicyChange(
    sub,
    signPolicyChange(ownerActors.slice(0, 2), { walletId: 'plain', ...sub }),
  );
  wallet.executeTask(task.id);
  assert.deepEqual(wallet.currentOwners, [newbie.address]);
  assert.equal(wallet.requiredConfirmations, 1n);
});

test('有档位钱包：所有者数低于最大档的缩编即使调高新确认数也被拒绝', () => {
  const { wallet, ownerActors } = tieredWallet(4, 1n, [
    { minimumValue: 1n, confirmations: 4n },
  ]); // 最大档 4
  const newbie = generateKeyPair();
  // 4 名当前所有者都签名，但新集合只有 3 人（新确认数 1 ≤ 3，本应通过基线字段校验）
  const sub = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: [ownerActors[0]!.address, ownerActors[1]!.address, newbie.address],
    newConfirmations: 1n,
  };
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        sub,
        signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...sub }),
      ),
    InvalidPolicyChange,
  );
});

// ============================================================
// 普通交易分阶段审批
// ============================================================

test('单笔审批：创建时按金额快照阈值；ready/提交/摘要与直接提交一致', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  const sub = { nonce: 0n, deadline: DEADLINE, to, value: 10_000n, data: new Uint8Array() };
  const approval = wallet.createTransactionApproval(sub);
  assert.equal(approval.confirmations, 3n); // 快照为金额档，而非全局 1
  assert.equal(approval.status, 'collecting');
  assert.equal(wallet.expectedNonce, 0n); // 创建不消费

  const d = hashTransactionApproval({ walletId: WALLET, version: 1n, ...sub });
  wallet.addApprovalSignature(approval.id, signDigest(ownerActors[0]!.privateKey, d));
  wallet.addApprovalSignature(approval.id, signDigest(ownerActors[1]!.privateKey, d));
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'collecting');
  // 未达创建时阈值 → ApprovalThresholdNotMetError，不消费 nonce、不建任务
  assert.throws(() => wallet.submitApprovedTransaction(approval.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);

  wallet.addApprovalSignature(approval.id, signDigest(ownerActors[2]!.privateKey, d));
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'ready');
  const task = wallet.submitApprovedTransaction(approval.id);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'submitted');
  assert.equal(wallet.expectedNonce, 1n);
  // 入队摘要仍是既有 safe-wallet/tx/v1（不含档位）
  assert.equal(task.digest, hashTransaction({ walletId: WALLET, ...sub }).toString('hex'));
});

test('单笔审批：高档审批的阈值与直接提交同源——2 签既不能直接提交也不能提交审批', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  const sub = { nonce: 0n, deadline: DEADLINE, to, value: 50_000n, data: new Uint8Array() };
  const approval = wallet.createTransactionApproval(sub);
  assert.equal(approval.confirmations, 4n);
  const d = hashTransactionApproval({ walletId: WALLET, version: 1n, ...sub });
  for (const k of ownerActors.slice(0, 3)) {
    wallet.addApprovalSignature(approval.id, signDigest(k.privateKey, d));
  }
  assert.throws(() => wallet.submitApprovedTransaction(approval.id), ApprovalThresholdNotMetError);
  assert.equal(wallet.expectedNonce, 0n);
});

// ============================================================
// 批量 / 策略审批
// ============================================================

test('批量审批：阈值按 calls 总额；提交后任务摘要即 tx-batch/v1', () => {
  const { wallet, ownerActors } = tieredWallet();
  const cs = calls([[4_000n], [8_000n]]); // 总额 12_000 → 3 签
  const approval = wallet.createBatchApproval({ nonce: 0n, deadline: DEADLINE, calls: cs });
  assert.equal(approval.confirmations, 3n);
  const d = hashBatchApproval({ walletId: WALLET, version: 1n, nonce: 0n, deadline: DEADLINE, calls: cs });
  for (const k of ownerActors.slice(0, 2)) {
    wallet.addBatchApprovalSignature(approval.id, signDigest(k.privateKey, d));
  }
  assert.throws(() => wallet.submitBatchApproval(approval.id), ApprovalThresholdNotMetError);
  wallet.addBatchApprovalSignature(approval.id, signDigest(ownerActors[2]!.privateKey, d));
  const task = wallet.submitBatchApproval(approval.id);
  assert.equal(
    task.digest,
    hashTransactionBatch({ walletId: WALLET, nonce: 0n, deadline: DEADLINE, calls: cs }).toString('hex'),
  );
  assert.equal(wallet.expectedNonce, 1n);
});

test('策略审批：恒按最大档收集；新所有者数低于最大档在创建时即拒绝', () => {
  const { wallet, ownerActors } = tieredWallet();
  // 3 名新所有者 < 最大档 4 → 创建即 InvalidPolicyChange
  assert.throws(
    () =>
      wallet.createPolicyApproval({
        version: 1n,
        nonce: 0n,
        deadline: DEADLINE,
        newOwners: addresses(ownerActors).slice(0, 3),
        newConfirmations: 1n,
      }),
    InvalidPolicyChange,
  );

  const sub = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const approval = wallet.createPolicyApproval(sub);
  assert.equal(approval.confirmations, 4n);
  const d = hashPolicyApproval({ walletId: WALLET, ...sub });
  for (const k of ownerActors.slice(0, 3)) {
    wallet.addPolicyApprovalSignature(approval.id, signDigest(k.privateKey, d));
  }
  assert.throws(() => wallet.submitApprovedPolicyChange(approval.id), ApprovalThresholdNotMetError);
  wallet.addPolicyApprovalSignature(approval.id, signDigest(ownerActors[3]!.privateKey, d));
  const task = wallet.submitApprovedPolicyChange(approval.id);
  assert.equal(task.digest, hashPolicyChange({ walletId: WALLET, ...sub }).toString('hex'));
});

// ============================================================
// 任务取消：按目标任务有效阈值
// ============================================================

test('取消：高档单笔任务需金额档签名，不足 → InvalidCancellation', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  // 高档任务 nonce 0 入队（4 签），先不执行
  const txTask = wallet.submitTransaction(
    { nonce: 0n, deadline: DEADLINE, to, value: 50_000n },
    txSigs(ownerActors, [0, 1, 2, 3], { to, value: 50_000n }),
  );
  const cancelFields = {
    walletId: WALLET,
    taskDigest: txTask.digest,
    nonce: 1n,
    deadline: DEADLINE,
  };
  // 3 签不足目标任务有效阈值 4
  assert.throws(
    () => wallet.cancelTask(txTask.id, 1n, DEADLINE, signCancellation(ownerActors.slice(0, 3), cancelFields)),
    InvalidCancellation,
  );
  assert.equal(wallet.getTask(txTask.id)?.status, 'queued');
  assert.equal(wallet.expectedNonce, 1n); // 取消失败不消费
  // 4 签成功取消
  const cancelled = wallet.cancelTask(
    txTask.id,
    1n,
    DEADLINE,
    signCancellation(ownerActors.slice(0, 4), cancelFields),
  );
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(wallet.expectedNonce, 2n);
});

test('取消：批量任务按总额档；策略变更任务按最大档', () => {
  const { wallet, ownerActors } = tieredWallet();
  // 批量总额 51_000 → 4；任务 nonce 0
  const cs = calls([[25_000n], [26_000n]]);
  const batchTask = wallet.submitBatchTransaction(
    { nonce: 0n, deadline: DEADLINE, calls: cs },
    batchSigs(ownerActors, [0, 1, 2, 3], cs, 0n),
  );
  const cf = { walletId: WALLET, taskDigest: batchTask.digest, nonce: 1n, deadline: DEADLINE };
  assert.throws(
    () => wallet.cancelTask(batchTask.id, 1n, DEADLINE, signCancellation(ownerActors.slice(0, 3), cf)),
    InvalidCancellation,
  );
  wallet.cancelTask(batchTask.id, 1n, DEADLINE, signCancellation(ownerActors.slice(0, 4), cf));
  assert.equal(wallet.getTask(batchTask.id)?.status, 'cancelled');

  // 策略任务 nonce 2 → 取消 nonce 3；恒需最大档 4
  const pc = {
    version: 1n,
    nonce: 2n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const policyTask = wallet.proposePolicyChange(
    pc,
    signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...pc }),
  );
  const cf2 = { walletId: WALLET, taskDigest: policyTask.digest, nonce: 3n, deadline: DEADLINE };
  assert.throws(
    () => wallet.cancelTask(policyTask.id, 3n, DEADLINE, signCancellation(ownerActors.slice(0, 3), cf2)),
    InvalidCancellation,
  );
  wallet.cancelTask(policyTask.id, 3n, DEADLINE, signCancellation(ownerActors.slice(0, 4), cf2));
  assert.equal(wallet.getTask(policyTask.id)?.status, 'cancelled');
});

// ============================================================
// 统一审批撤销：按目标审批有效阈值
// ============================================================

function revokeFields(approvalDigest: string, nonce: bigint) {
  return { walletId: WALLET, approvalDigest, nonce, deadline: DEADLINE };
}

test('撤销：高档单笔审批需金额档签名，不足 → ApprovalRevocationThresholdNotMetError', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: DEADLINE, to, value: 10_000n });
  // 2 签撤销 < 有效阈值 3
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: DEADLINE },
        signApprovalRevocation(ownerActors.slice(0, 2), revokeFields(approval.digest, 0n)),
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'collecting');
  assert.equal(wallet.expectedNonce, 0n);
  // 3 签撤销成功
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: DEADLINE },
    signApprovalRevocation(ownerActors.slice(0, 3), revokeFields(approval.digest, 0n)),
  );
  assert.equal(revoked.status, 'revoked');
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.tasks.length, 0);
});

test('撤销：低档（未命中）单笔审批 1 签即可；批量审批按总额档', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();

  // 未命中任何档 → 全局 1 签
  const low = wallet.createTransactionApproval({ nonce: 0n, deadline: DEADLINE, to, value: 500n });
  assert.equal(low.confirmations, 1n);
  const r1 = wallet.revokeApproval(
    { approvalId: low.id, nonce: 0n, deadline: DEADLINE },
    signApprovalRevocation([ownerActors[0]!], revokeFields(low.digest, 0n)),
  );
  assert.equal(r1.status, 'revoked');

  // 批量总额 12_000 → 3 签
  const cs = calls([[4_000n], [8_000n]]);
  const batch = wallet.createBatchApproval({ nonce: 1n, deadline: DEADLINE, calls: cs });
  assert.equal(batch.confirmations, 3n);
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: batch.id, nonce: 1n, deadline: DEADLINE },
        signApprovalRevocation(ownerActors.slice(0, 2), revokeFields(batch.digest, 1n)),
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  const r2 = wallet.revokeApproval(
    { approvalId: batch.id, nonce: 1n, deadline: DEADLINE },
    signApprovalRevocation(ownerActors.slice(0, 3), revokeFields(batch.digest, 1n)),
  );
  assert.equal(r2.status, 'revoked');
});

test('撤销：策略审批恒按最大档', () => {
  const { wallet, ownerActors } = tieredWallet();
  const sub = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const approval = wallet.createPolicyApproval(sub);
  assert.equal(approval.confirmations, 4n);
  assert.throws(
    () =>
      wallet.revokeApproval(
        { approvalId: approval.id, nonce: 0n, deadline: DEADLINE },
        signApprovalRevocation(ownerActors.slice(0, 3), revokeFields(approval.digest, 0n)),
      ),
    ApprovalRevocationThresholdNotMetError,
  );
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 0n, deadline: DEADLINE },
    signApprovalRevocation(ownerActors.slice(0, 4), revokeFields(approval.digest, 0n)),
  );
  assert.equal(revoked.status, 'revoked');
});

test('撤销：未命中档位的 conflicted 审批，在全局确认数下调后按当前阈值撤销（旧行为不回归）', () => {
  // 4 所有者、全局 2 签、仅有高档（10_000 → 4 签）：小额审批未命中档位
  const ownerActors = actors(4);
  const wallet = new MultiSigWallet({
    id: WALLET,
    owners: addresses(ownerActors),
    confirmations: 2n,
    valueThresholds: [{ minimumValue: 10_000n, confirmations: 4n }],
    now: () => 1000n,
  });
  const to = recipient();
  const approval = wallet.createTransactionApproval({ nonce: 0n, deadline: DEADLINE, to, value: 7n });
  assert.equal(approval.confirmations, 2n);

  // 策略漂移：保持 4 名所有者（≥ 最大档 4），仅把全局确认数降到 1
  const pc = {
    version: 1n,
    nonce: 0n,
    deadline: DEADLINE,
    newOwners: addresses(ownerActors),
    newConfirmations: 1n,
  };
  const t = wallet.proposePolicyChange(
    pc,
    signPolicyChange(ownerActors.slice(0, 4), { walletId: WALLET, ...pc }),
  );
  wallet.executeTask(t.id);
  assert.equal(wallet.getTransactionApproval(approval.id).status, 'conflicted');

  // 未命中档位 → 撤销阈值按当前全局 1 签；任意一名当前所有者即可
  const revoked = wallet.revokeApproval(
    { approvalId: approval.id, nonce: 1n, deadline: DEADLINE },
    signApprovalRevocation([ownerActors[3]!], revokeFields(approval.digest, 1n)),
  );
  assert.equal(revoked.status, 'revoked');
});

// ============================================================
// 端到端：成功路径的回执 / FIFO / 幂等不变
// ============================================================

test('端到端：高档单笔与批量任务的执行回执、FIFO 与幂等与无规则钱包一致', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  const t1 = wallet.submitTransaction(
    { nonce: 0n, deadline: DEADLINE, to, value: 50_000n, data: Buffer.from('hi') },
    txSigs(ownerActors, [0, 1, 2, 3], { to, value: 50_000n, data: Buffer.from('hi') }),
  );
  const cs = calls([[40_000n], [11_000n]]); // 51_000 → 4 签
  const t2 = wallet.submitBatchTransaction(
    { nonce: 1n, deadline: DEADLINE, calls: cs },
    batchSigs(ownerActors, [0, 1, 2, 3], cs, 1n),
  );

  // 不能越序执行 t2（FIFO：只有队首可执行）
  assert.throws(() => wallet.executeTask(t2.id), InvalidQueueStateError);
  const d1 = wallet.executeTask(t1.id);
  assert.deepEqual(d1.receipt?.result, {
    kind: 'transfer',
    to,
    value: 50_000n,
    data: Buffer.from('hi').toString('hex'),
  });
  const d2 = wallet.executeNext()!;
  assert.equal((d2.receipt!.result as { kind: string }).kind, 'transfer-batch');
  // 幂等：重复执行不重复生效
  assert.equal(wallet.executeTask(t1.id), d1);
  assert.equal(wallet.executeTask(t2.id), d2);
});

test('失败不建任务、不消费 nonce、不改 owners/confirmations/version/审批/队列', () => {
  const { wallet, ownerActors } = tieredWallet();
  const to = recipient();
  // 先成功一笔小额
  wallet.submitTransaction(
    { nonce: 0n, deadline: DEADLINE, to, value: 10n },
    txSigs(ownerActors, [0], { to, value: 10n }),
  );
  const snapshot = {
    nonce: wallet.expectedNonce,
    tasks: wallet.tasks.length,
    version: wallet.policyVersion,
    owners: wallet.currentOwners,
    confirmations: wallet.requiredConfirmations,
  };
  // 高档金额只给 1 签 → 失败
  assert.throws(
    () =>
      wallet.submitTransaction(
        { nonce: 1n, deadline: DEADLINE, to, value: 50_000n },
        txSigs(ownerActors, [0], { nonce: 1n, to, value: 50_000n }),
      ),
    InvalidTransaction,
  );
  // 高档批量只给 1 签 → 失败
  const cs = calls([[25_000n], [26_000n]]);
  assert.throws(
    () => wallet.submitBatchTransaction({ nonce: 1n, deadline: DEADLINE, calls: cs }, batchSigs(ownerActors, [0], cs, 1n)),
    InvalidTransactionBatch,
  );
  assert.deepEqual(
    {
      nonce: wallet.expectedNonce,
      tasks: wallet.tasks.length,
      version: wallet.policyVersion,
      owners: wallet.currentOwners,
      confirmations: wallet.requiredConfirmations,
    },
    snapshot,
  );
});
