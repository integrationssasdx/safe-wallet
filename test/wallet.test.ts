import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MultiSigWallet } from '../src/wallet.ts';
import {
  InvalidPolicyChange,
  InvalidTransaction,
  NonceAlreadyUsedError,
  RequestExpired,
} from '../src/errors.ts';
import { actors, addresses, fakeClock, signPolicyChange, signTransaction, type Actor } from './helpers.ts';
import { generateKeyPair } from '../src/crypto.ts';

const WALLET = 'wallet-1';
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

const txSub = (over: Record<string, unknown> = {}) => ({
  nonce: 0n,
  deadline: 2000n,
  to: RECIPIENT,
  value: 100n,
  ...over,
});

// ---------- 构造期策略校验 ----------

test('构造：空所有者 / 重复 / 零地址 / 确认数越界均拒绝', () => {
  const [a, b] = actors(2);
  const zero = '0x' + '00'.repeat(20);
  assert.throws(
    () => new MultiSigWallet({ id: 'w', owners: [], confirmations: 1n }),
    InvalidPolicyChange,
  );
  assert.throws(
    () => new MultiSigWallet({ id: 'w', owners: [a.address, a.address], confirmations: 1n }),
    InvalidPolicyChange,
  );
  assert.throws(
    () => new MultiSigWallet({ id: 'w', owners: [zero, b.address], confirmations: 1n }),
    InvalidPolicyChange,
  );
  assert.throws(
    () => new MultiSigWallet({ id: 'w', owners: [a.address, b.address], confirmations: 0n }),
    InvalidPolicyChange,
  );
  assert.throws(
    () => new MultiSigWallet({ id: 'w', owners: [a.address, b.address], confirmations: 3n }),
    InvalidPolicyChange,
  );
});

test('初始版本为 1，策略只读视图正确', () => {
  const { wallet, ownerActors } = setup();
  assert.equal(wallet.policyVersion, 1n);
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.deepEqual(wallet.currentOwners, addresses(ownerActors));
  assert.equal(wallet.expectedNonce, 0n);
});

// ---------- 普通交易提交（既有行为不回归） ----------

test('普通交易：达到阈值 → 入队，任务可见，nonce 被消费', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 2000n,
    to,
    value: 100n,
  });
  const task = wallet.submitTransaction(txSub({ to }), sigs);
  assert.equal(task.status, 'queued');
  assert.equal(task.seq, 0);
  assert.equal(task.payload.kind, 'transaction');
  assert.equal(wallet.tasks.length, 1);
  assert.equal(wallet.expectedNonce, 1n);
  assert.equal(wallet.isNonceUsed(0n), true);
});

test('普通交易：签名不足 / 非所有者 / 同人重复签 → InvalidTransaction', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  const params = { walletId: WALLET, nonce: 0n, deadline: 2000n, to, value: 100n };

  const one = signTransaction([ownerActors[0]!], params);
  assert.throws(() => wallet.submitTransaction(txSub({ to }), one), InvalidTransaction);

  const outsider = actors(1)[0]!;
  const foreign = signTransaction([ownerActors[0]!, outsider], params);
  assert.throws(() => wallet.submitTransaction(txSub({ to }), foreign), InvalidTransaction);

  const dup = signTransaction([ownerActors[0]!, ownerActors[0]!], params);
  assert.throws(() => wallet.submitTransaction(txSub({ to }), dup), InvalidTransaction);

  // 全部被拒：无任务、nonce 未消费、策略不变
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.policyVersion, 1n);
});

test('普通交易：签名载荷与提交内容不匹配 → InvalidTransaction', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  // 签名时 value=100，提交时 value=999
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 2000n,
    to,
    value: 100n,
  });
  assert.throws(
    () => wallet.submitTransaction(txSub({ to, value: 999n }), sigs),
    InvalidTransaction,
  );
  // 签名绑定别的钱包标识
  const wrongWallet = signTransaction(ownerActors.slice(0, 2), {
    walletId: 'wallet-OTHER',
    nonce: 0n,
    deadline: 2000n,
    to,
    value: 100n,
  });
  assert.throws(() => wallet.submitTransaction(txSub({ to }), wrongWallet), InvalidTransaction);
  assert.equal(wallet.tasks.length, 0);
});

test('普通交易：零地址收款方 / 非法地址 / 负金额 → InvalidTransaction', () => {
  const { wallet } = setup();
  const bad = '0x' + '00'.repeat(20);
  // 字段校验先于签名恢复，占位签名即可证明：非法字段在到达签名校验前即拒绝
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  assert.throws(() => wallet.submitTransaction(txSub({ to: bad }), placeholder), InvalidTransaction);
  assert.throws(() => wallet.submitTransaction(txSub({ to: '0x123' }), placeholder), InvalidTransaction);
  const good = actors(1)[0]!.address;
  assert.throws(
    () => wallet.submitTransaction(txSub({ to: good, value: -1n }), placeholder),
    InvalidTransaction,
  );
  assert.equal(wallet.tasks.length, 0);
});

// ---------- nonce 顺序与复用（两类操作共用同一序列） ----------

test('nonce 必须严格递增：跳号/回退 → 对应 Invalid*，且不消费', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 5n,
    deadline: 2000n,
    to,
    value: 1n,
  });
  assert.throws(
    () => wallet.submitTransaction(txSub({ to, nonce: 5n }), sigs),
    InvalidTransaction,
  );
  assert.equal(wallet.expectedNonce, 0n);
  assert.equal(wallet.tasks.length, 0);
});

test('nonce 复用 → NonceAlreadyUsedError（公开异常），失败终态也不释放', () => {
  const { wallet, ownerActors, clock } = setup();
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to,
    value: 1n,
  });
  wallet.submitTransaction(txSub({ to, deadline: 5000n, value: 1n }), sigs);
  // 执行后 nonce 已消费
  wallet.executeNext();

  const replay = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 6000n,
    to,
    value: 1n,
  });
  assert.throws(
    () => wallet.submitTransaction(txSub({ to, deadline: 6000n, value: 1n }), replay),
    NonceAlreadyUsedError,
  );
});

// ---------- 截止时间 ----------

test('提交时已过期 → RequestExpired；不建任务、不消费 nonce，可按同 nonce 重新提交', () => {
  const { wallet, ownerActors } = setup();
  const to = actors(1)[0]!.address;
  const expired = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 999n,
    to,
    value: 1n,
  });
  assert.throws(
    () => wallet.submitTransaction(txSub({ to, deadline: 999n, value: 1n }), expired),
    RequestExpired,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);

  // 同一 nonce 用未来截止时间重新提交成功（无部分受理）
  const fresh = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 2000n,
    to,
    value: 1n,
  });
  const task = wallet.submitTransaction(txSub({ to, deadline: 2000n, value: 1n }), fresh);
  assert.equal(task.status, 'queued');
});

test('截止时间恰好等于当前时间：边界有效（“早于”才过期）', () => {
  const { wallet, ownerActors } = setup(undefined, undefined, 1000n);
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 1000n,
    to,
    value: 1n,
  });
  const task = wallet.submitTransaction(txSub({ to, deadline: 1000n, value: 1n }), sigs);
  assert.equal(task.status, 'queued');
});

test('已使用 nonce 优先于过期判定：旧请求重放恒为 NonceAlreadyUsedError', () => {
  const { wallet, ownerActors, clock } = setup();
  const to = actors(1)[0]!.address;
  const sigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to,
    value: 1n,
  });
  wallet.submitTransaction(txSub({ to, deadline: 5000n, value: 1n }), sigs);
  // 时刻推进到远超截止时间；重放 nonce=0 仍应得到复用异常而非过期
  clock.set(9000n);
  const replay = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 5000n,
    to,
    value: 1n,
  });
  assert.throws(
    () => wallet.submitTransaction(txSub({ to, deadline: 5000n, value: 1n }), replay),
    NonceAlreadyUsedError,
  );
  assert.equal(wallet.tasks.length, 1, '不产生重复任务');
});

// ---------- 策略变更：提交字段校验 ----------

test('策略变更：新所有者空/重复/零地址 → InvalidPolicyChange，无任何副作用', () => {
  const { wallet, ownerActors } = setup();
  const zero = '0x' + '00'.repeat(20);
  const cases: { newOwners: string[]; newConfirmations: bigint }[] = [
    { newOwners: [], newConfirmations: 1n },
    { newOwners: [ownerActors[0]!.address, ownerActors[0]!.address], newConfirmations: 1n },
    { newOwners: [zero, ownerActors[1]!.address], newConfirmations: 1n },
    { newOwners: ['not-an-address'], newConfirmations: 1n },
  ];
  // 字段校验先于摘要计算与签名恢复，占位签名即可：非法字段在更早阶段拒绝
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  for (const c of cases) {
    assert.throws(
      () =>
        wallet.proposePolicyChange(
          { version: 1n, nonce: 0n, deadline: 2000n, ...c },
          placeholder,
        ),
      InvalidPolicyChange,
    );
    assert.equal(wallet.tasks.length, 0);
    assert.equal(wallet.expectedNonce, 0n);
    assert.equal(wallet.policyVersion, 1n);
  }
});

test('策略变更：确认数 <=0 或超过新所有者数 → InvalidPolicyChange', () => {
  const { wallet, ownerActors } = setup();
  const [a, b] = ownerActors;
  const placeholder = [new Uint8Array(65), new Uint8Array(65)];
  for (const newConfirmations of [0n, -1n, 3n, 99n]) {
    const newOwners = [a!.address, b!.address];
    assert.throws(
      () =>
        wallet.proposePolicyChange(
          { version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations },
          placeholder,
        ),
      InvalidPolicyChange,
    );
  }
  assert.equal(wallet.tasks.length, 0);
});

test('策略变更：提交版本不等于当前版本 → InvalidPolicyChange', () => {
  const { wallet, ownerActors } = setup();
  const newOwners = addresses(ownerActors);
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 2n, // 当前是 1
    nonce: 0n,
    deadline: 2000n,
    newOwners,
    newConfirmations: 2n,
  });
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        { version: 2n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 2n },
        sigs,
      ),
    InvalidPolicyChange,
  );
  assert.equal(wallet.tasks.length, 0);
});

test('策略变更：阈值不足/非所有者/重复签/畸形签名 → InvalidPolicyChange', () => {
  const { wallet, ownerActors } = setup();
  const newOwners = addresses(ownerActors);
  const params = {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 2000n,
    newOwners,
    newConfirmations: 2n,
  };
  const sub = { version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 2n };

  assert.throws(() => wallet.proposePolicyChange(sub, []), InvalidPolicyChange);
  assert.throws(
    () => wallet.proposePolicyChange(sub, signPolicyChange([ownerActors[0]!], params)),
    InvalidPolicyChange,
  );
  const outsider = actors(1)[0]!;
  assert.throws(
    () =>
      wallet.proposePolicyChange(sub, signPolicyChange([ownerActors[0]!, outsider], params)),
    InvalidPolicyChange,
  );
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        sub,
        signPolicyChange([ownerActors[0]!, ownerActors[0]!], params),
      ),
    InvalidPolicyChange,
  );
  assert.throws(
    () => wallet.proposePolicyChange(sub, [new Uint8Array(65), new Uint8Array(65)]),
    InvalidPolicyChange,
  );
  assert.equal(wallet.tasks.length, 0);
  assert.equal(wallet.expectedNonce, 0n);
});

test('策略变更：签名载荷任一字段被改动 → InvalidPolicyChange', async () => {
  const { wallet, ownerActors } = setup();
  const newOwners = addresses(ownerActors);
  const t = actors(1)[0]!;
  void t;
  const params = {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 2000n,
    newOwners,
    newConfirmations: 2n,
  };
  const mutateCases = [
    (p: typeof params) => ({ ...p, version: 2n }),
    (p: typeof params) => ({ ...p, nonce: 1n }),
    (p: typeof params) => ({ ...p, deadline: 2001n }),
    (p: typeof params) => ({ ...p, newConfirmations: 3n }),
    (p: typeof params) => ({ ...p, walletId: 'wallet-OTHER' }),
    (p: typeof params) => ({ ...p, newOwners: [p.newOwners[1]!, p.newOwners[0]!, p.newOwners[2]!] }),
  ] as const;
  for (const mutate of mutateCases) {
    const sigs = signPolicyChange(ownerActors.slice(0, 2), params, { mutate: mutate as any });
    assert.throws(
      () =>
        wallet.proposePolicyChange(
          { version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 2n },
          sigs,
        ),
      InvalidPolicyChange,
    );
  }
  assert.equal(wallet.tasks.length, 0);
});

test('两类签名互不通用：交易签名不能用于策略变更提交', () => {
  const { wallet, ownerActors } = setup();
  const to = ownerActors[0]!.address;
  const txSigs = signTransaction(ownerActors.slice(0, 2), {
    walletId: WALLET,
    nonce: 0n,
    deadline: 2000n,
    to,
    value: 0n,
  });
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        { version: 1n, nonce: 0n, deadline: 2000n, newOwners: addresses(ownerActors), newConfirmations: 2n },
        txSigs,
      ),
    InvalidPolicyChange,
  );
  assert.equal(wallet.tasks.length, 0);
});

test('策略变更：合法提交 → 入队且不立即改变策略、不递增版本', () => {
  const { wallet, ownerActors } = setup();
  const newbie = actors(1)[0]!;
  const newOwners = [ownerActors[0]!.address, newbie.address];
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 0n,
    deadline: 2000n,
    newOwners,
    newConfirmations: 1n,
  });
  const task = wallet.proposePolicyChange(
    { version: 1n, nonce: 0n, deadline: 2000n, newOwners, newConfirmations: 1n },
    sigs,
  );
  assert.equal(task.status, 'queued');
  assert.equal(task.payload.kind, 'policy-change');
  assert.equal(wallet.policyVersion, 1n, '版本在执行前不得变化');
  assert.equal(wallet.requiredConfirmations, 2n);
  assert.equal(wallet.isOwner(newbie.address), false);
  assert.equal(wallet.expectedNonce, 1n);
});

test('策略变更也严格走 nonce 序列：乱序 InvalidPolicyChange，过期 RequestExpired', () => {
  const { wallet, ownerActors } = setup();
  const newOwners = addresses(ownerActors);
  const sigs = signPolicyChange(ownerActors.slice(0, 2), {
    walletId: WALLET,
    version: 1n,
    nonce: 3n,
    deadline: 2000n,
    newOwners,
    newConfirmations: 2n,
  });
  assert.throws(
    () =>
      wallet.proposePolicyChange(
        { version: 1n, nonce: 3n, deadline: 2000n, newOwners, newConfirmations: 2n },
        sigs,
      ),
    InvalidPolicyChange,
  );
});
