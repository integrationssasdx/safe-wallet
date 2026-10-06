/**
 * 引擎公开错误类型。
 *
 * 设计约定：
 * - 提交阶段（普通交易 / 策略变更）对“内容不合法”的判定互不混用：
 *   普通交易 → InvalidTransaction；策略变更 → InvalidPolicyChange。
 * - RequestExpired 仅用于截止时间已过；PolicyConflict 仅用于执行时版本已漂移。
 * - NonceAlreadyUsedError 是既有重放防护的公开异常，策略变更沿用同一类型。
 */

export class WalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** 普通交易提交参数或签名不合法 */
export class InvalidTransaction extends WalletError {}

/**
 * 原子批量普通交易提交不合法（不建任务、不消费 nonce、不改策略/队列）：
 * 列表为空或超过 64 项、收款地址非法或为零、金额越界、data 不是 Uint8Array、
 * 签名集合畸形、签名者非当前所有者、去重签名不足当前确认数。
 */
export class InvalidTransactionBatch extends WalletError {}

/** 策略变更字段、版本、签名或 nonce 顺序不合法（不建任务、不消费 nonce、不改策略） */
export class InvalidPolicyChange extends WalletError {}

/** 请求截止时间早于当前时间（提交时与执行时均可出现，不产生任务/不进入终态） */
export class RequestExpired extends WalletError {}

/** 执行时发现任务绑定的策略版本已不是当前版本；任务进入既有失败终态 */
export class PolicyConflict extends WalletError {}

/** nonce 已经被使用 —— 既有重放防护的公开异常，普通交易与策略变更共用 */
export class NonceAlreadyUsedError extends WalletError {
  readonly usedNonce: bigint;
  constructor(nonce: bigint) {
    super(`nonce already used: ${nonce}`);
    this.usedNonce = nonce;
  }
}

/** 取消请求字段、nonce 顺序或签名不合法（不改变任务、不消费 nonce、不改策略） */
export class InvalidCancellation extends WalletError {}

/** 目标任务已处于终态（executed / failed / cancelled），不可再取消 */
export class TaskCancellationConflict extends WalletError {}

/** 对不存在任务、终态任务重复执行等队列层面的非法操作 */
export class TaskNotFoundError extends WalletError {}

export class InvalidQueueStateError extends WalletError {}

// ---------- 分阶段审批（普通交易 / 策略变更 / 批量交易共用同一组错误） ----------

/** 审批 id 不存在（创建之外的加签 / 查询 / 提交均抛此异常） */
export class ApprovalNotFoundError extends WalletError {}

/** 同一所有者对同一审批重复加签 */
export class DuplicateApprovalSignatureError extends WalletError {}

/** 审批签名格式非法（非 65 字节）、与摘要不符或签名者不是当前所有者 */
export class InvalidApprovalSignatureError extends WalletError {}

/** 审批截止时间已过（加签 / 提交时抛出；查询状态为 expired） */
export class ApprovalExpiredError extends WalletError {}

/** 审批创建后策略版本已漂移（加签 / 提交时抛出；查询状态为 conflicted；过期优先于此） */
export class ApprovalPolicyConflictError extends WalletError {}

/** 审批已完成提交（之后加签 / 重复提交抛出；查询状态为 submitted） */
export class ApprovalAlreadySubmittedError extends WalletError {}

/** 提交时收集到的去重签名数不足审批创建时的确认数 */
export class ApprovalThresholdNotMetError extends WalletError {}

/** 提交时审批绑定的 nonce 不等于当前 expectedNonce（尚未被消费但顺序不符） */
export class ApprovalNonceConflictError extends WalletError {}

// ---------- 统一审批撤销（普通交易 / 策略变更 / 批量交易审批共用） ----------

/**
 * 撤销请求本身不合法：approvalId 非字符串、nonce/deadline 无法安全转换或越界、
 * 签名集合畸形（非数组、空、元素非 65 字节、签名无法恢复）。
 * 校验顺序中最先发生（字段层），失败不消费 nonce、不改变任何状态。
 */
export class InvalidApprovalRevocationRequest extends WalletError {}

/**
 * 撤销签名无效：签名与 safe-wallet/approval-revoke/v1 摘要不匹配（恢复出的签名者
 * 对不上任何当前所有者），或签名者不是当前所有者。跨钱包 / 跨审批 / 其他操作域的
 * 签名在此一并拒绝。
 */
export class InvalidApprovalRevocationSigner extends WalletError {}

/** 撤销请求收集到的去重当前所有者签名数不足当前确认数 */
export class ApprovalRevocationThresholdNotMetError extends WalletError {}

/** 撤销请求 nonce 未耗用但不等于当前 expectedNonce（顺序错；nonce 复用仍抛 NonceAlreadyUsedError） */
export class InvalidApprovalRevocationNonceError extends WalletError {}

/**
 * 目标审批与撤销操作冲突：审批已撤销（重复撤销 / 再加签 / 再提交）或已提交
 * （对应任务已建立，撤销不适用；其未消费 nonce 的取消走既有 cancelTask）。
 */
export class ApprovalRevocationConflictError extends WalletError {}

// ---------- 静态分级支出阈值 ----------

/**
 * 分级支出阈值策略不合法（构造钱包时抛出，不创建实例）：
 * minimumValue 非正、达到或超过 2^256、未严格递增；confirmations 非安全正整数、
 * 低于全局确认数、高于所有者数量或随金额下降。
 */
export class InvalidSpendingPolicy extends WalletError {}

/** 支出阈值查询金额不合法：负数或达到 / 超过 2^256（不消费 nonce、不建任务、不改状态） */
export class InvalidSpendingValueError extends WalletError {}
