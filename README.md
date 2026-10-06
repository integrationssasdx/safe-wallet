# Safe Wallet

多签钱包策略引擎：阈值策略、签名收集、重放防护、执行队列、策略变更任务、任务取消、
**原子批量普通交易**、普通交易 / 策略变更 / 批量交易的**分阶段审批**（登记与提交分离、逐个加签），
以及三类未提交审批共用的**统一审批撤销**。

本仓库从零实现上述能力，不依赖任何外部同类实现或第三方密码学/以太坊库（仅使用 Node.js 内置的
`node:crypto` 提供 SHA-256/HMAC 与随机数；secp256k1 点运算、RFC 6979 签名与公钥恢复均为内置实现）。

## 运行环境

- Node.js ≥ 22.6（直接运行 TypeScript，依赖运行时的类型擦除；无需编译步骤）
- 无运行时第三方依赖

```bash
npm install        # 仅安装类型检查所需的 devDependencies（typescript / @types/node）
npm test           # 运行全部测试
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
- **原子批量普通交易（transaction-batch）**：一个有序调用列表（每项含收款地址、金额、
  `Uint8Array` data），**非空且最多 64 项，顺序不得改变**。整批只入队一个队列任务、
  只消费一个 nonce；成功执行整批产生一个 `transfer-batch` 回执，**不产生部分执行回执**。
- **策略变更（policy-change）**：绑定提交时的当前策略版本、新所有者列表、新确认数、nonce、
  截止时间。执行成功时**原子地**同时替换所有者集合与确认数，并令版本递增一次。

各类操作使用不同的域分隔标签，因此单笔交易、批量交易、策略变更、取消的签名两两互不通用。

### 原子批量普通交易

`submitBatchTransaction` 接收 `{ nonce, deadline, calls }` 与签名数组。批量摘要使用独立域标签
`safe-wallet/tx-batch/v1`，绑定**钱包标识、nonce、deadline 与按顺序编码的全部调用**
（每调用固定按“收款地址 || 金额 || data”编码，再以数量前缀绑定项数与顺序）：

- 单笔交易、策略变更、取消签名都**不能**授权批量交易，批量签名也不能授权单笔交易；
- 任一调用的收款方、金额、data，或调用顺序、项数变化，都会改变摘要；
- 金额、nonce、deadline 沿用既有非负整数口径（256 位以内）。

校验顺序与单笔提交一致（查 nonce → 查 deadline → 校验内容与签名）。下列情形一律抛
`InvalidTransactionBatch`，且**失败时不创建任务、不消费 nonce、不改变策略或队列**：
列表为空或超过 64 项、收款地址非法或为零、数值越界、data 不是 `Uint8Array`、签名集合畸形、
签名者非当前所有者、去重签名不足当前确认数。

成功时只入队一个批量任务、只消费本次 nonce 并推进 `expectedNonce`，队列摘要防重继续生效。
批量任务沿用同一 FIFO 队列：`executeTask` / `executeNext` 的选中规则、越序限制与终态幂等
均不变；重复执行返回同一任务与同一回执。`cancelTask` 可取消尚未执行的批量任务，保留其
payload、digest、nonce 及既有取消时间与摘要，不产生调用结果，不改变 owners、confirmations
或 policyVersion。

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

## 分阶段审批（登记与提交分离、逐个加签）

普通交易、策略变更与批量交易都支持“先登记、逐个收集签名、阈值满足后再提交”的分阶段审批，
三者规则同构、命名空间与域标签各自独立；审批与对应直接提交的签名摘要互不通用。

| 操作 | 普通交易审批 | 策略变更审批 | 批量交易审批 |
| --- | --- | --- | --- |
| 创建（登记） | `createTransactionApproval` | `createPolicyApproval` | `createBatchApproval` |
| 加签（每次一个 65 字节签名） | `addApprovalSignature` | `addPolicyApprovalSignature` | `addBatchApprovalSignature` |
| 阈值满足后提交 | `submitApprovedTransaction` | `submitApprovedPolicyChange` | `submitBatchApproval` |
| 查询单个 / 列出全部 | `getTransactionApproval` / — | `getPolicyApproval` / `listPolicyApprovals` | `getBatchApproval` / `listBatchApprovals` |
| 撤销（三类共用） | `revokeApproval({ approvalId, nonce, deadline }, signatures)`（同左，按 id 统一查找） | 同左 | 同左 |

- **创建只登记**：校验与对应直接提交一致，但**不消费 nonce、不建任务、不改策略**。因此同一
  nonce 可以登记多个候选审批（内容可不同，由各自 id 区分；id 按创建序号派生，即使摘要相同
  也互不冲突）。创建时绑定当时的策略版本、确认数（阈值）、nonce、deadline 与完整目标内容，
  并复制保存输入（策略审批复制新所有者列表），调用方之后改动原对象不影响审批。
- **加签只收集**：`addApprovalSignature` / `addPolicyApprovalSignature` / `addBatchApprovalSignature`
  每次只收一个 **65 字节**签名，恢复签名者并校验其为**当前所有者**，按加签顺序去重记录；登记加签不改
  策略、nonce、队列。收集到的去重签名数达到**创建时确认数**后，状态由 `collecting` 变
  `ready`。
- **提交才生效**：阈值满足后由 `submitApproved*` / `submitBatchApproval` 按**既有直接提交域**的
  摘要入队一个任务（普通交易 → `safe-wallet/tx/v1`；策略变更 → `safe-wallet/policy-change/v1`；
  批量交易 → `safe-wallet/tx-batch/v1`），只消费
  **创建时绑定的 nonce** 并推进 `expectedNonce`，审批进入 `submitted` 终态。之后的执行、
  取消、终态幂等等队列行为与直接提交完全一致；策略变更审批任务执行时若版本已漂移，仍按既有
  **`PolicyConflict`** 进入失败终态、不改策略。

审批摘要使用独立域标签：

- 普通交易审批：`safe-wallet/tx-approval/v1`，绑定钱包标识、创建时版本、nonce、deadline 与
  完整交易字段（收款方、金额、data）。
- 策略变更审批：`safe-wallet/policy-change-approval/v1`，绑定**钱包标识、版本、nonce、
  deadline 与目标新策略**（新确认数、按顺序编码的新所有者列表）。新所有者顺序参与签名，
  顺序变化即改变摘要。
- 批量交易审批：`safe-wallet/tx-batch-approval/v1`，绑定**钱包标识、版本、nonce、deadline
  与按顺序编码的全部调用**（每调用固定按“收款地址 || 金额 || data”编码，再以数量前缀绑定
  项数与顺序）。任一调用的收款方、金额、data，或调用顺序、项数变化，都会改变摘要。

状态（查询时按此刻时钟/版本派生）优先级固定为
`revoked > submitted > expired > conflicted > ready > collecting`：

| 状态 | 含义 |
| --- | --- |
| `collecting` | 未过期、版本未漂移、签名尚未达到创建时确认数 |
| `ready` | 签名已达阈值，可提交 |
| `submitted` | 已提交（终态；再加签 / 重复提交抛 `ApprovalAlreadySubmittedError`） |
| `expired` | deadline 已过（加签 / 提交抛 `ApprovalExpiredError`，优先于版本冲突；仍可撤销） |
| `conflicted` | 创建后策略版本已漂移（加签 / 提交抛 `ApprovalPolicyConflictError`；仍可撤销） |
| `revoked` | 已被统一审批撤销（终态，优先级最高；加签 / 提交 / 再撤销抛 `ApprovalRevocationConflictError`） |

创建的校验顺序与对应直接提交一致，任一失败都**不产生记录、不消费 nonce、不改策略/队列**：

1. 字段安全转换失败 / nonce 已用 → 普通交易审批 `InvalidTransaction`、策略变更审批
   `InvalidPolicyChange`、批量审批 `InvalidTransactionBatch`；nonce 已用 →
   `NonceAlreadyUsedError`（复用判定优先于过期）。
2. deadline 早于当前时间 → `RequestExpired`。
3. 其余内容校验（nonce 须等于 `expectedNonce`；策略审批另查版本须等于当前版本、新所有者
   列表与新确认数合法性；批量审批另查 calls 为 1..64 项、收款地址、金额与 data）
   → 对应 `Invalid*`。

加签 / 提交的校验顺序（任一失败都不改变审批与任何既有状态）：

1. 未知 id → `ApprovalNotFoundError`；已提交 → `ApprovalAlreadySubmittedError`。
2. 已过期 → `ApprovalExpiredError`；版本漂移 → `ApprovalPolicyConflictError`（过期优先）。
3. 加签：签名非 65 字节 / 畸形、与审批摘要不符、签名者非当前所有者 →
   `InvalidApprovalSignatureError`；同一所有者重复加签 → `DuplicateApprovalSignatureError`。
4. 提交：去重签名数不足创建时确认数 → `ApprovalThresholdNotMetError`。
5. 提交：绑定 nonce 已被消费（含被同批其他候选或直接提交消费）→ `NonceAlreadyUsedError`；
   nonce 尚未耗用但不等于当前 `expectedNonce`（顺序错）→ `ApprovalNonceConflictError`。

`listPolicyApprovals()` / `listBatchApprovals()` 按**创建顺序**返回全部对应审批快照；三类审批
各自独立编号、互不可见。

## 统一审批撤销

普通交易、策略变更与批量交易三类**尚未提交**的分阶段审批共用一个撤销入口
`revokeApproval({ approvalId, nonce, deadline }, signatures)`：按审批 id 在三类审批命名空间中
统一查找目标，阈值签名使用独立域标签 `safe-wallet/approval-revoke/v1`，绑定**钱包标识、
目标审批自身的审批域摘要（tx-approval / policy-change-approval / tx-batch-approval）、nonce、
截止时间**。因此撤销签名无法改绑其他钱包或其他审批，也不能授权交易、批量、策略变更、取消或
审批加签等任何其他操作；三类审批的撤销互相同构。

- **只覆盖未提交审批**：`submitted` 审批不可撤销（抛 `ApprovalRevocationConflictError`）；
  已过期（`expired`）或版本漂移（`conflicted`）的审批**仍可撤销**——撤销请求有自己独立的
  nonce 与 deadline，签名者按**当前**所有者集合与当前确认数校验。
- **成功只消费一次 nonce**：撤销与提交 / 取消共用同一严格递增 nonce 序列（入队 / 生效即消费）。
  成功后审批进入 `revoked` 终态并返回其快照：**不建任务、不产回执**，不改 owners、
  confirmations、policyVersion 或任何既有任务，也不影响其他未撤销审批。
- **快照保留签名者但失效**：`revoked` 快照仍含已收集的 `signers`（按加签顺序）与撤销记录
  `revocation`（撤销时间、撤销摘要、消费的 nonce 与 deadline），但审批永久失效。状态优先级
  变为 `revoked > submitted > expired > conflicted > ready > collecting`：撤销后即使审批原
  deadline 已过或版本继续漂移，状态恒为 `revoked`；再加签、再撤销或提交一律抛
  `ApprovalRevocationConflictError`。

校验顺序固定为 **字段 → nonce 复用 → deadline → nonce 顺序 → 审批存在性 → 审批状态 → 签名**，
任一失败都不撤销、不消费 nonce、不改审批 / 策略 / 队列：

1. `approvalId` 非字符串（或空）、nonce / deadline 字段非法、签名不是 65 字节或签名数组畸形
   （非数组 / 空数组 / 含非字节数组）→ `InvalidApprovalRevocationRequest`。
2. nonce 已使用 → `NonceAlreadyUsedError`（旧请求重放恒得此异常，即使已过期）。
3. deadline 早于当前时间 → `RequestExpired`（恰好相等仍有效）。
4. nonce 未使用但不等于当前 `expectedNonce`（顺序错）→ `InvalidApprovalRevocationNonceError`。
5. 三类审批命名空间均无该 id → `ApprovalNotFoundError`。
6. 审批已撤销或已提交 → `ApprovalRevocationConflictError`（`expired` / `conflicted` 不在此列）。
7. 阈值签名：签名与撤销摘要不匹配（含跨钱包、跨审批及其他操作的签名）或签名者非当前所有者
   → `InvalidApprovalRevocationSigner`；去重后的当前所有者签名数不足当前确认数
   → `ApprovalRevocationThresholdNotMetError`。

直接提交、nonce 防重、FIFO 队列、任务取消、批量原子回执、策略生效以及**已提交任务的
`cancelTask` 处理均保持不变**；未撤销审批的创建、加签、提交、执行、批量、幂等、队列与异常
行为也完全不变。

## 提交流程（普通交易、批量交易与策略变更共用）

对每次提交，系统按顺序核对，任一失败都**不创建任务、不消费 nonce、不改变当前策略**：

1. **nonce 复用** → 抛出 `NonceAlreadyUsedError`（既有重放防护的公开异常，各类操作共用）。
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
- **批量交易**：整批一次性执行并产出**一个** `transfer-batch` 回执，`calls` 按输入顺序给出
  规范化收款地址、原金额与十六进制 data；不会逐调用产出部分执行回执（回调正常返回才写
  executed，抛出则整批 failed）。同样不触碰策略状态。
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
| `InvalidTransactionBatch` | 批量交易列表（空/超 64 项）、调用字段（地址/金额/data）、nonce 顺序或签名不合法 |
| `InvalidPolicyChange` | 策略变更字段、版本（提交时）、nonce 顺序或签名不合法 |
| `InvalidCancellation` | 取消请求字段、nonce 顺序或签名不合法 |
| `TaskCancellationConflict` | 取消目标已处于终态（executed / failed / cancelled） |
| `RequestExpired` | 截止时间早于当前时间（提交时抛出；执行时表现为失败终态回执原因） |
| `PolicyConflict` | 执行时任务绑定版本已不等于当前版本（失败终态） |
| `NonceAlreadyUsedError` | nonce 已被使用（公开重放异常，含 `.usedNonce`） |
| `TaskNotFoundError` | 执行/查询不存在的任务 id |
| `InvalidQueueStateError` | 跳过队首执行等非法队列操作 |
| `ApprovalNotFoundError` | 加签 / 查询 / 提交使用了不存在的审批 id |
| `InvalidApprovalSignatureError` | 审批加签非 65 字节 / 畸形、与审批摘要不符或签名者非当前所有者 |
| `DuplicateApprovalSignatureError` | 同一所有者对同一审批重复加签 |
| `ApprovalExpiredError` | 审批已过期时加签 / 提交（过期优先于版本冲突） |
| `ApprovalPolicyConflictError` | 审批创建后策略版本漂移时加签 / 提交 |
| `ApprovalAlreadySubmittedError` | 对已提交审批再加签或重复提交 |
| `ApprovalThresholdNotMetError` | 提交审批时去重签名数不足创建时确认数 |
| `ApprovalNonceConflictError` | 提交审批时绑定 nonce 未耗用但不等于当前 `expectedNonce`（顺序错） |
| `InvalidApprovalRevocationRequest` | 审批撤销请求字段（approvalId 非字符串、nonce / deadline 非法）或签名集合外形不合法 |
| `InvalidApprovalRevocationSigner` | 撤销签名与撤销摘要不匹配（含跨钱包、跨审批、其他操作签名）或签名者非当前所有者 |
| `ApprovalRevocationThresholdNotMetError` | 撤销请求去重后的当前所有者签名数不足当前确认数 |
| `InvalidApprovalRevocationNonceError` | 撤销 nonce 未耗用但不等于当前 `expectedNonce`（顺序错） |
| `ApprovalRevocationConflictError` | 撤销已提交 / 已撤销审批，或对已撤销审批再加签、再撤销、提交 |

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
- 批量交易域标签：`safe-wallet/tx-batch/v1`，字段为钱包标识、nonce、截止时间、调用列表
  （`encList`；每个调用固定编码为收款地址、金额、data 三段，顺序即列表顺序）。
- 策略变更域标签：`safe-wallet/policy-change/v1`，字段为钱包标识、版本、nonce、截止时间、
  新确认数、新所有者列表。
- 任务取消域标签：`safe-wallet/cancel/v1`，字段为钱包标识、目标任务 digest、nonce、截止时间。
- 普通交易审批域标签：`safe-wallet/tx-approval/v1`，字段为钱包标识、创建时版本、nonce、
  截止时间、收款方、金额、数据（与直接提交域不同，审批签名不能用于直接提交，反之亦然）。
- 策略变更审批域标签：`safe-wallet/policy-change-approval/v1`，字段为钱包标识、创建时版本、
  nonce、截止时间、新确认数、新所有者列表；提交时仍改用 `safe-wallet/policy-change/v1`
  摘要入队。
- 批量交易审批域标签：`safe-wallet/tx-batch-approval/v1`，字段为钱包标识、创建时版本、
  nonce、截止时间与按顺序编码的全部调用；提交时仍改用 `safe-wallet/tx-batch/v1` 摘要入队。
- 统一审批撤销域标签：`safe-wallet/approval-revoke/v1`，字段为钱包标识、目标审批自身的审批域
  摘要（hex，即三类审批各自的 tx-approval / policy-change-approval / tx-batch-approval 摘要）、
  nonce、截止时间。撤销签名与上述所有域（含三类审批加签、直接提交与取消）互不通用。

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
  encoding.ts  规范化长度前缀编码与各类操作（含批量交易、三类分阶段审批与统一审批撤销）的签名摘要
  errors.ts    公开错误类型
  queue.ts     FIFO 执行队列（排序、终态、幂等、digest 防重）
  wallet.ts    多签钱包引擎（阈值、签名收集、nonce、提交校验、批量、策略应用、分阶段审批与撤销）
  index.ts     统一导出
test/          node:test 测试（密码学、编码、队列、提交、执行、批量、取消、三类审批、统一撤销、对抗输入）
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
  { to: c.address, value: 200n, data: Buffer.from('calldata') },
];
const digest = hashTransactionBatch({
  walletId: 'wallet-1',
  nonce: wallet.expectedNonce, // 整批一个 nonce
  deadline: 5000n,
  calls,
});
const sigs = [a, b].map((k) => signDigest(k.privateKey, digest));

const batchTask = wallet.submitBatchTransaction(
  { nonce: 0n, deadline: 5000n, calls },
  sigs,
);
const executed = wallet.executeTask(batchTask.id);
(executed.receipt!.result as { kind: string }).kind; // 'transfer-batch'
// result.calls 按输入顺序给出 { to, value, data(hex) }；整批只有这一个回执
```

### 策略变更分阶段审批

```ts
import { hashPolicyApproval } from './src/encoding.ts';

const target = {
  version: wallet.policyVersion, // 绑定创建时版本 1n
  nonce: wallet.expectedNonce,   // 0n；创建不消费
  deadline: 5000n,
  newOwners: [a.address, newbie.address],
  newConfirmations: 1n,
};

// 1) 登记（不消费 nonce、不建任务、不改策略）；同一 nonce 可登记多个候选
const approval = wallet.createPolicyApproval(target);

// 2) 当前所有者逐个加签（65 字节；safe-wallet/policy-change-approval/v1 域）
const approvalDigest = hashPolicyApproval({ walletId: 'wallet-1', ...target });
for (const k of [a, b]) {
  wallet.addPolicyApprovalSignature(approval.id, signDigest(k.privateKey, approvalDigest));
}
wallet.getPolicyApproval(approval.id).status; // 'ready'

// 3) 阈值满足后提交：按既有 policy-change/v1 摘要入队，消费创建时 nonce
const task = wallet.submitApprovedPolicyChange(approval.id);
wallet.getPolicyApproval(approval.id).status; // 'submitted'
wallet.executeTask(task.id);                  // 执行成功才替换策略、版本 1 → 2
```

### 批量交易分阶段审批

```ts
import { hashBatchApproval } from './src/encoding.ts';

const batch = {
  nonce: wallet.expectedNonce, // 创建不消费
  deadline: 5000n,
  calls: [
    { to: b.address, value: 100n, data: new Uint8Array() },
    { to: c.address, value: 200n, data: Buffer.from('calldata') },
  ],
};

// 1) 登记（不消费 nonce、不建任务、不改策略）；同一 nonce 可登记多个候选
const approval = wallet.createBatchApproval(batch);

// 2) 当前所有者逐个加签（65 字节；safe-wallet/tx-batch-approval/v1 域）
const approvalDigest = hashBatchApproval({
  walletId: 'wallet-1',
  version: wallet.policyVersion,
  ...batch,
});
for (const k of [a, b]) {
  wallet.addBatchApprovalSignature(approval.id, signDigest(k.privateKey, approvalDigest));
}
wallet.getBatchApproval(approval.id).status; // 'ready'

// 3) 阈值满足后提交：按既有 tx-batch/v1 摘要入队一个 transaction-batch 任务，
//    只消费创建时 nonce；执行仍产出单个 transfer-batch 原子回执
const task = wallet.submitBatchApproval(approval.id);
wallet.getBatchApproval(approval.id).status; // 'submitted'
wallet.executeTask(task.id).receipt!.result; // { kind: 'transfer-batch', calls: [...] }
```

### 统一审批撤销

```ts
import { hashApprovalRevocation } from './src/encoding.ts';

// 任意一类未提交审批（普通交易 / 策略变更 / 批量交易）均可撤销；expired / conflicted 也可以
const pending = wallet.createTransactionApproval({
  nonce: wallet.expectedNonce, // 0n；创建不消费
  deadline: 5000n,
  to: b.address,
  value: 10n,
});

// 撤销请求使用自己的下一个期望 nonce；摘要绑定钱包、目标审批摘要、nonce、deadline
const revokeDigest = hashApprovalRevocation({
  walletId: 'wallet-1',
  approvalDigest: pending.digest,
  nonce: wallet.expectedNonce, // 0n（撤销与提交/取消共用序列）
  deadline: 5000n,
});
const revokeSigs = [a, b].map((k) => signDigest(k.privateKey, revokeDigest));

const revoked = wallet.revokeApproval(
  { approvalId: pending.id, nonce: 0n, deadline: 5000n },
  revokeSigs,
);
revoked.status;                 // 'revoked'
revoked.signers;                // 已收集签名者保留（此处为空）
revoked.revocation!.digest;     // safe-wallet/approval-revoke/v1 撤销摘要
wallet.expectedNonce;           // 1n（只消费一次 nonce）
wallet.tasks.length;            // 0（不建任务、不产回执）

// 已撤销审批永久失效：加签 / 提交 / 再撤销都抛 ApprovalRevocationConflictError
```

## 约定

- 公开行为以本 README 与源码为准。
- 后续需求在此基线上增量实现；新增策略变更流程只改变策略变更自身的可观察行为，
  普通交易从收集签名到入队再到执行的既有结果保持不变。
