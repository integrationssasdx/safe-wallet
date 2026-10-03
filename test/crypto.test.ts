import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  generateKeyPair,
  keyPairFromPrivate,
  recoverAddress,
  recoverPublicKey,
  signDigest,
  sha256,
  addressFromPublicKey,
  ZERO_ADDRESS,
  hexToBytes,
} from '../src/crypto.ts';

test('生成的密钥对：地址可由公钥复现，签名可恢复回签名者', () => {
  for (let i = 0; i < 10; i++) {
    const kp = generateKeyPair();
    assert.equal(kp.publicKey.length, 65);
    assert.equal(kp.privateKey.length, 32);
    assert.match(kp.address, /^0x[0-9a-f]{40}$/);
    assert.equal(addressFromPublicKey(kp.publicKey), kp.address);

    const digest = sha256(Buffer.from(`payload-${i}`));
    const sig = signDigest(kp.privateKey, digest);
    assert.equal(sig.length, 65);
    assert.equal(recoverAddress(digest, sig), kp.address);
  }
});

test('确定性签名：同一私钥与摘要两次签名逐字节一致（RFC 6979）', () => {
  const kp = generateKeyPair();
  const digest = sha256(Buffer.from('deterministic'));
  assert.deepEqual(signDigest(kp.privateKey, digest), signDigest(kp.privateKey, digest));
});

test('签名总为 low-s；手工翻转成 high-s 后被拒绝', () => {
  const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  const kp = generateKeyPair();
  const digest = sha256(Buffer.from('low-s'));
  const sig = signDigest(kp.privateKey, digest);
  const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
  assert.ok(s <= N >> 1n);

  const highS = N - s;
  const flipped = Buffer.from(sig);
  flipped.subarray(32, 64).set(
    (() => {
      const b = Buffer.alloc(32);
      let v = highS;
      for (let i = 31; i >= 0; i--) b[i] = Number(v & 0xffn), (v >>= 8n);
      return b;
    })(),
  );
  // 恢复位也需翻转才在数学上对应同一公钥；无论如何 high-s 一律拒绝
  flipped.writeUInt8(flipped.readUInt8(64) ^ 1, 64);
  assert.equal(recoverAddress(digest, flipped), null);
});

test('篡改签名或摘要 → 恢复出不同地址或失败', () => {
  const kp = generateKeyPair();
  const digest = sha256(Buffer.from('original'));
  const sig = Buffer.from(signDigest(kp.privateKey, digest));

  // 篡改 r 一个字节
  const tampered = Buffer.from(sig);
  tampered.writeUInt8(tampered.readUInt8(0) ^ 0xff, 0);
  assert.notEqual(recoverAddress(digest, tampered), kp.address);

  // 换摘要
  assert.notEqual(recoverAddress(sha256(Buffer.from('other')), sig), kp.address);
});

test('畸形签名：长度错误 / recoveryId 越界 / 零 r 被拒绝', () => {
  const digest = sha256(Buffer.from('x'));
  assert.equal(recoverAddress(digest, new Uint8Array(64)), null);
  assert.equal(recoverAddress(digest, new Uint8Array(66)), null);

  const kp = generateKeyPair();
  const sig = Buffer.from(signDigest(kp.privateKey, digest));
  sig.writeUInt8(4, 64);
  assert.equal(recoverAddress(digest, sig), null);

  const zeroR = Buffer.alloc(65);
  zeroR.subarray(32, 64).set(hexToBytes('0x' + '01'.repeat(32)));
  assert.equal(recoverAddress(digest, zeroR), null);
});

test('摘要长度非法时拒绝恢复', () => {
  const kp = generateKeyPair();
  const sig = signDigest(kp.privateKey, sha256(Buffer.from('x')));
  assert.equal(recoverAddress(new Uint8Array(31), sig), null);
});

test('私钥可从 32 字节重建并导出同一地址', () => {
  const kp = generateKeyPair();
  const rebuilt = keyPairFromPrivate(kp.privateKey);
  assert.deepEqual(rebuilt.publicKey, kp.publicKey);
  assert.equal(rebuilt.address, kp.address);
});

test('非法私钥（越界 / 长度错）抛错', () => {
  assert.throws(() => keyPairFromPrivate(new Uint8Array(31)));
  assert.throws(() => keyPairFromPrivate(new Uint8Array(32)));
  const over = new Uint8Array(32).fill(0xff);
  assert.throws(() => keyPairFromPrivate(over));
});

test('零地址常量', () => {
  assert.equal(ZERO_ADDRESS, '0x' + '00'.repeat(20));
});

// 随机往返压力（随机消息 + 随机密钥，恢复必须成立）
test('50 组随机密钥/消息的签名恢复往返', () => {
  for (let i = 0; i < 50; i++) {
    const kp = generateKeyPair();
    const digest = createHash('sha256').update(randomBytes(40)).digest();
    const sig = signDigest(kp.privateKey, digest);
    assert.equal(recoverAddress(digest, sig), kp.address);
  }
});

// 用 Node 原生 ECDSA 独立验证“恢复出的公钥”确实能验过 r||s（不依赖本实现的地址推导）
const SECP256K1_SPKI_PREFIX = Buffer.from(
  '3056301006072a8648ce3d020106052b8104000a034200',
  'hex',
);

test('恢复出的公钥可通过 Node 原生 ECDSA 独立验签（20 组）', () => {
  for (let i = 0; i < 20; i++) {
    const kp = generateKeyPair();
    const message = randomBytes(32);
    const digest = createHash('sha256').update(message).digest();
    const sig65 = signDigest(kp.privateKey, digest);
    const pub65 = recoverPublicKey(digest, sig65);
    assert.ok(pub65);
    const spki = Buffer.concat([SECP256K1_SPKI_PREFIX, pub65!]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const rs = sig65.subarray(0, 64);
    // 标准模式：原生库对 message 做 SHA-256 后验签 r||s
    const valid = cryptoVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, rs);
    assert.equal(valid, true);
  }
});

// 覆盖 recoveryId 高位 j=1（R.x = r + N）分支：该情形自然概率约 2^-128，无法靠随机命中。
// 这里用一份独立的最小曲线实现，自行取一个横坐标 x>=N 的曲线点 R，再按恢复公式
// Q = r^-1(sR - eG) 反推 Q，构造 65 字节签名，断言库内恢复得到同一个 Q。
test('j=1 恢复分支：合成 R.x >= N 的签名可正确恢复公钥', () => {
  const P = 2n ** 256n - 2n ** 32n - 977n;
  const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  const Gx = BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240');
  const Gy = BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424');
  const mod = (a: bigint) => ((a % P) + P) % P;
  const modN = (a: bigint) => ((a % N) + N) % N;
  const inv = (a: bigint, m: bigint) => {
    let [oldR, r] = [((a % m) + m) % m, m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    return ((oldS % m) + m) % m;
  };
  type Pt = { x: bigint; y: bigint } | null;
  const add = (a: Pt, b: Pt): Pt => {
    if (!a) return b;
    if (!b) return a;
    if (a.x === b.x && a.y !== b.y) return null;
    const lam =
      a.x === b.x && a.y === b.y
        ? mod(3n * a.x * a.x * inv(mod(2n * a.y), P))
        : mod((b.y - a.y) * inv(mod(b.x - a.x), P));
    const x = mod(lam * lam - a.x - b.x);
    return { x, y: mod(lam * (a.x - x) - a.y) };
  };
  const mul = (k: bigint, p: Pt): Pt => {
    let r: Pt = null;
    let q = p;
    while (k > 0n) {
      if (k & 1n) r = add(r, q);
      q = add(q, q);
      k >>= 1n;
    }
    return r;
  };
  const toBytes = (n: bigint, len = 32) => {
    const out = Buffer.alloc(len);
    let v = n;
    for (let i = len - 1; i >= 0; i--) out[i] = Number(v & 0xffn), (v >>= 8n);
    return out;
  };

  // 在 (N, P) 内找一个有曲线上点的横坐标（必须严格大于 N，使 r=Rx-N 落在 1..N-1）
  let Rx = N + 1n;
  let Ry: bigint | null = null;
  for (; Rx < N + 1000n; Rx++) {
    const alpha = mod(Rx * Rx * Rx + 7n);
    const y = mod(modPow(alpha, (P + 1n) / 4n, P));
    if (mod(y * y) === alpha) {
      Ry = y;
      break;
    }
  }
  function modPow(b: bigint, e: bigint, m: bigint) {
    let r = 1n;
    b = ((b % m) + m) % m;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  }
  assert.ok(Ry !== null, '应找到 x>=N 的曲线点');
  assert.ok(Rx >= N, '前置条件：R.x 落在 [N,P)');
  const parity = Number(Ry! & 1n);

  const e = 123n;
  const s = 1n;
  const r = Rx - N; // 0 < r < N
  // Q = r^-1 (s R - e G)
  const sR: Pt = { x: Rx, y: Ry! };
  const eG = mul(e, { x: Gx, y: Gy });
  const negEG: Pt = eG ? { x: eG.x, y: mod(-eG.y) } : null;
  const sum = add(sR, negEG)!;
  const Q = mul(inv(r, N), sum)!;
  const expectedPub = Buffer.concat([Buffer.from([4]), toBytes(Q.x), toBytes(Q.y)]);

  const digest = toBytes(e);
  const sig = Buffer.concat([
    toBytes(r),
    toBytes(s),
    Buffer.from([2 | parity]), // j=1
  ]);
  const recovered = recoverPublicKey(digest, sig);
  assert.ok(recovered !== null);
  assert.ok(recovered!.equals(expectedPub), 'j=1 分支应恢复出反推出的 Q');
  assert.equal(recoverAddress(digest, sig), addressFromPublicKey(expectedPub));
});
