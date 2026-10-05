# Safe Wallet

多签钱包策略引擎：阈值策略、签名收集、重放防护、执行队列、策略变更任务、**任务取消**，以及
**原子批量普通交易**。

本仓库从零实现上述能力，不依赖任何外部同类实现或第三方密码学/以太坊库（仅使用 Node.js 内置的
`node:crypto` 提供 SHA-256/HMAC 与随机数；secp256k1 点运算、RFC 6979 签名与公钥恢复均为内置实现）。

## 运行环境

- Node.js ≥ 22.6（直接运行 TypeScript，依赖运行时的类型擦除；无需编译步骤）
- 无运行时第三方依赖

```bash
npm install        # 仅安装类型检查所需的 devDependencies（typescript / @types/node）
npm test           # 运行全部 104 项测试
npm run typecheck  # 严格类型检查
```

## 模型概览

一个钱包由以下状态描述：

| 状态 | 含义 |
| --- | --- |
| `owners` | 当前所有者地址集合（有序、唯一、非零地址） |
| `confirmations` | 当前阈值（确认数），`1 <= confirmations <= owners.length` |
| `version` | 当前策略版本，初始为 `1`，**每次成功执行策略变更恰好递增一次**（取消不递增） |
| `nonce` 序列 | 普通交易、批量交易、策略变更与取消**共用**的严格递增序列号，入队/生效即消费 |
| 执行队列 | FIFO：只有队首可执行；任务有 `queued / executed / failed / cancelled` 四态，终态不可逆 |

### 三类任务

- **普通交易（transaction）**：收款方、金额、附带数据。其签名载荷**不包含策略版本字段**，
  与既有流程完全一致。
- **原子批量普通交易（transaction-batch）**：一个有序调用列表（非空、至多 64 项，每项含
  收款地址、金额、`Uint8Array` data）。整批共用一个 nonce、一个签名集合、一个队列任务；
  执行时整批生效，只产生一个 `result.kind === 'transfer-batch'` 的回执（**无部分执行
  回执**）。其签名载荷同样不含策略版本字段。
- **策略变更（policy-change）**：绑定提交时的当前策略版本、新所有者列表、新确认数、nonce、
  截止时间。执行成功时**原子地**同时替换所有者集合与确认数，并令版本递增一次。

各类操作使用不同的域分隔标签，因此任一操作的签名都不能用于其他操作（普通交易签名不能用于
批量交易/策略变更，反之亦然）。

### 任务取消

当前所有者可以撤销一个尚未执行的 `queued` 任务：`cancelTask` 接收目标任务 id、nonce、
截止时间与签名数组。取消摘要使用独立的域标签 `safe-wallet/cancel/v1`，绑定**钱包标识、
目标任务 digest、nonce、截止时间**——签名无法改绑其他任务、其他钱包或其他时间窗口，
三类操作的签名也互不通用。

校验顺序（任一失败都**不改变任务、不消费 nonce、不改变策略**）：

1. 字段非法 → `InvalidCancellation`；
2. nonce 复用 → `NonceAlreadyUsedError`（旧请求重放恒得此异常，即使已过期）；
3. deadline 早于当前时间 → `RequestExpired`；
4. nonce 顺序（须等于 `expectedNonce`）→ `InvalidCancellation`；
5. 目标不存在 → `TaskNotFoundError`；目标已是 `executed / failed / cancelled` →
   `TaskCancellationConflict`；
6. 阈值签名（当前所有者、去重后达到当前确认数）→ `InvalidCancellation`。

成功时目标任务由 `queued` 进入 `cancelled` 终态并返回：保留原 payload/digest/nonce，
记录取消时间与取消摘要（`task.cancellation`）；**不执行目标效果，不改变 owners、确认数
或策略版本**，只消费本次 nonce 并推进 `expectedNonce`。取消不要求任务在队首，也不调整
队列顺序；`executeTask` 对 cancelled 任务直接返回终态（不产生效果），`executeNext`
越过队首或连续的 cancelled 任务执行首个 `queued` 任务，剩余全是终态时返回 `null`。

### 原子批量普通交易

`submitBatchTransaction({ nonce, deadline, calls }, signatures)` 提交一个有序调用列表：

- `calls` **非空且至多 64 项**（`MAX_BATCH_CALLS`），每项为 `{ to, value, data? }`；
  收款地址必须合法且非零，金额为非负 256 位整数，`data` 必须是 `Uint8Array`（缺省为空）。
- **顺序即承诺**：提交、签名、保存、执行与回执全部保持同一顺序，不排序、不去重。
- 摘要使用独立域标签 `safe-wallet/tx-batch/v1`（**不含策略版本**，与普通交易一致），绑定
  **钱包标识、nonce、deadline、按顺序编码的全部调用**。任一调用的地址/金额/data 变化、
  调用顺序变化或调用数量变化都会改变摘要；普通交易、策略变更、取消的签名都不能授权批量
  交易，批量签名也不能用于其他三类操作。

校验顺序与单笔提交一致（任一失败都**不创建任务、不消费 nonce、不改变策略或队列**）：

1. nonce 复用 → `NonceAlreadyUsedError`（优先于过期判定）；
2. deadline 早于当前时间 → `RequestExpired`；
3. nonce 顺序、调用列表与字段、阈值签名（当前所有者、去重后达到当前确认数）→
   `InvalidTransactionBatch`。

成功时**只入队一个批量任务、只消费本次 nonce 并推进 `expectedNonce`**；队列层面的摘要防重
继续生效。执行沿用既有 FIFO 规则（仅队首可执行、越序拒绝、终态幂等）：整批执行成功后产生
**一个**回执，`receipt.result` 形如

```ts
{
  kind: 'transfer-batch',
  calls: [
    { to: '0x…（规范化小写地址）', value: 10n, data: '…（十六进制，空 data 为 ""）' },
    // …按输入顺序给出全部调用；不产生部分执行回执
  ],
}
```

重复执行返回同一任务与同一回执。尚未执行的批量任务可被 `cancelTask` 取消：保留其
payload、digest、nonce 及既有取消时间与取消摘要，不产生调用结果，不改变 owners、
confirmations 或 policyVersion。截止时间同样只在提交阶段核对，不是执行闸门。

## 提交流程（普通交易、批量交易与策略变更共用）

对每次提交，系统按顺序核对，任一失败都**不创建任务、不消费 nonce、不改变当前策略**：

1. **nonce 复用** → 抛出 `NonceAlreadyUsedError`（既有重放防护的公开异常，两类操作共用）。
2. **截止时间早于当前时间** → 抛出 `RequestExpired`。
3. **字段 / 版本 / nonce 顺序 / 签名** →
   - 普通交易：`InvalidTransaction`
   - 批量交易：`InvalidTransactionBatch`
   - 策略变更：`InvalidPolicyChange`
4. 全部通过后：计算签名摘要 → 恢复签名者 → 地址去重 → 校验签名者均为**当前所有者**且
   去重后的数量达到**当前确认数** → 入队并消费 nonce。

> nonce 顺序必须严格连续（下一个期望值可通过 `wallet.expectedNonce` 读取）。跳号、回退都按
> 对应操作的 `Invalid*` 拒绝。nonce 复用检查先于过期检查：一个旧请求即使已经过期，重放时仍
> 恒定得到 `NonceAlreadyUsedError`。

### 策略变更的额外字段规则

- 新所有者列表：**不能为空、不能有重复地址、不能包含零地址、每个地址必须合法**。
- 新确认数：**必须大于 0，且不超过新所有者数量**。
- 提交时绑定的版本必须**等于当前版本**，否则 `InvalidPolicyChange`（执行时才发现漂移的情形见下）。
- 签名载荷显式绑定：钱包标识、操作标签、当前版本、新所有者列表、新确认数、nonce、截止时间。
  任一字段与提交内容不一致都视为签名不匹配 → `InvalidPolicyChange`。

## 执行流程

- 只有**队首任务**可执行；任务在队列中按 FIFO 排序，提交后即对 `tasks` 快照可见。
  队首（或连续）的 `cancelled` 任务视为已越过：`executeNext` 执行首个 `queued` 任务，
  剩余全是终态时返回 `null`。
- **普通交易**：执行产出转账结果（收款方/金额/数据），不触碰策略状态。
- **原子批量普通交易**：执行产出一个 `transfer-batch` 结果，`calls` 按输入顺序给出规范化
  收款地址、原金额与十六进制 data；整批只有一个回执，不产生部分执行回执；不触碰策略状态。
- **策略变更**：
  - 执行的生效条件是穷尽的：**任务绑定版本仍等于当前版本，且队列允许执行（队首）**。
  - 若执行时绑定版本 **≠ 当前版本**（执行前策略已被别的任务改变）→ 任务进入 `failed`
    终态，回执原因为 **`PolicyConflict`**，策略内容不变、版本不再递增。
  - 否则所有者集合与确认数**同时替换**为提交值，版本递增一次，任务进入 `executed` 终态。
- 截止时间只在**提交阶段**核对（`RequestExpired`）；它不是执行闸门——一旦任务已合法入队，
  即使之后超过截止时间才执行，只要版本仍匹配就正常生效（普通交易的既有执行结果也因此不变）。
- 终态不可逆：对已终态任务重复执行直接返回既有回执，**不重复生效（幂等）**。失败终态的
  nonce 也不释放。
- 策略变更成功后，任何仍使用旧版本、旧 nonce、旧签名的请求都无法再次生效：
  - 旧版本在提交阶段即被 `InvalidPolicyChange` 拒绝；
  - 旧 nonce 被重放防护拒绝；
  - 旧签名摘要在队列历史上唯一，无法再次入队。

队列层面 digest 在全部历史任务（含失败终态）上唯一，作为 nonce 之外的又一层防重。

## 公开错误

| 错误 | 触发时机 |
| --- | --- |
| `InvalidTransaction` | 普通交易字段、nonce 顺序或签名不合法 |
| `InvalidTransactionBatch` | 批量交易的调用列表（空/超上限/地址非法或为零/金额越界/data 非字节数组）、nonce 顺序或签名不合法 |
| `InvalidPolicyChange` | 策略变更字段、版本（提交时）、nonce 顺序或签名不合法 |
| `InvalidCancellation` | 取消请求字段、nonce 顺序或签名不合法 |
| `TaskCancellationConflict` | 取消目标已处于终态（executed / failed / cancelled） |
| `RequestExpired` | 截止时间早于当前时间（提交时抛出；执行时表现为失败终态回执原因） |
| `PolicyConflict` | 执行时任务绑定版本已不等于当前版本（失败终态） |
| `NonceAlreadyUsedError` | nonce 已被使用（公开重放异常，含 `.usedNonce`） |
| `TaskNotFoundError` | 执行/查询不存在的任务 id |
| `InvalidQueueStateError` | 跳过队首执行等非法队列操作 |

提交路径对任意畸形输入（`undefined`、非数字字符串、小数、超大整数、畸形签名集合等）都只会
抛出上表中的约定错误，不会泄漏原生 `TypeError`/`RangeError`。

## 签名载荷编码

所有字段以大端、长度前缀方式规范化编码（避免拼接歧义，`["ab","c"]` 与 `["a","bc"]` 不等价）：

```
encBytes(b) = uint32(len(b)) || b
encStr(s)   = uint32(len(utf8(s))) || utf8(s)
encUint(n)  = 32 字节定长大端
encList(xs) = uint32(count) || concat(encBytes(x))

digest = sha256( encStr(domainTag) || 各字段 )
```

- 普通交易域标签：`safe-wallet/tx/v1`，字段为钱包标识、nonce、截止时间、收款方、金额、数据。
- 批量交易域标签：`safe-wallet/tx-batch/v1`，字段为钱包标识、nonce、截止时间、有序调用列表。
  列表以 `encList` 加数量前缀，每项依次为收款方（`encBytes(20 字节地址)`）、金额
  （`encUint`）、data（`encBytes`）；调用顺序与每项边界都由长度前缀固定，无拼接歧义，
  且不含策略版本字段。
- 策略变更域标签：`safe-wallet/policy-change/v1`，字段为钱包标识、版本、nonce、截止时间、
  新确认数、新所有者列表。
- 任务取消域标签：`safe-wallet/cancel/v1`，字段为钱包标识、目标任务 digest、nonce、截止时间。

## 密码学约定

- 地址 = `0x` + 小写十六进制（`sha256(未压缩公钥 65 字节)` 的末 20 字节）。
- 签名为 65 字节 `r(32) || s(32) || v(1)`，RFC 6979 确定性 nonce；**强制 low-s**，high-s 与
  可塑签名一律拒绝。`v` 为 secp256k1 公钥恢复标识（0..3）。
- 签名正确性有独立交叉验证：测试中用 Node 原生 ECDSA 对恢复出的公钥做验签；确定性 nonce
  与一份独立 Python 参考实现逐字节比对；并显式覆盖罕见的 `R.x ≥ N`（j=1）恢复分支。

## 代码结构

```
src/
  crypto.ts    secp256k1 点运算 / RFC6979 签名 / 公钥恢复 / 地址 / SHA-256
  encoding.ts  规范化长度前缀编码与四类操作（交易/批量交易/策略变更/取消）的签名摘要
  errors.ts    公开错误类型
  queue.ts     FIFO 执行队列（排序、终态、幂等、digest 防重）
  wallet.ts    多签钱包引擎（阈值、签名收集、nonce、提交校验、策略应用）
  index.ts     统一导出
test/          node:test 测试（密码学、编码、队列、提交、执行、对抗输入）
```

## 最小示例

```ts
import { MultiSigWallet } from './src/wallet.ts';
import { generateKeyPair, signDigest } from './src/crypto.ts';
import { hashPolicyChange } from './src/encoding.ts';

const [a, b, c] = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
let now = 1000n;
const wallet = new MultiSigWallet({
  id: 'wallet-1',
  owners: [a.address, b.address, c.address],
  confirmations: 2n,
  now: () => now,
});

const newbie = generateKeyPair();
const newOwners = [a.address, newbie.address];
const digest = hashPolicyChange({
  walletId: 'wallet-1',
  version: wallet.policyVersion, // 绑定当前版本 1n
  nonce: wallet.expectedNonce,   // 0n
  deadline: 5000n,
  newOwners,
  newConfirmations: 1n,
});
const sigs = [a, b].map((k) => signDigest(k.privateKey, digest));

const task = wallet.proposePolicyChange(
  { version: 1n, nonce: 0n, deadline: 5000n, newOwners, newConfirmations: 1n },
  sigs,
);
const done = wallet.executeTask(task.id);
done.status;                 // 'executed'
wallet.policyVersion;        // 2n
wallet.requiredConfirmations; // 1n
wallet.currentOwners;        // [a.address, newbie.address]
```

### 原子批量普通交易

```ts
import { hashTransactionBatch } from './src/encoding.ts';

const calls = [
  { to: b.address, value: 100n, data: new Uint8Array() },
  { to: c.address, value: 200n, data: Buffer.from('deadbeef', 'hex') },
];
const digest = hashTransactionBatch({
  walletId: 'wallet-1',
  nonce: wallet.expectedNonce,
  deadline: 5000n,
  calls,
});
const sigs = [a, b].map((k) => signDigest(k.privateKey, digest));

const batch = wallet.submitBatchTransaction({ nonce: 0n, deadline: 5000n, calls }, sigs);
const executed = wallet.executeTask(batch.id);
(executed.receipt!.result as { kind: string }).kind; // 'transfer-batch'
// result.calls 按顺序给出 { to, value, data(hex) }；整批只有这一个回执
```

## 约定

- 公开行为以本 README 与源码为准。
- 后续需求在此基线上增量实现；新增策略变更流程只改变策略变更自身的可观察行为，
  普通交易从收集签名到入队再到执行的既有结果保持不变。
