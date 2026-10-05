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

// ---------- 普通交易分阶段签名收集（审批） ----------

/** 审批不存在（未知 id；或从未创建） */
export class ApprovalNotFoundError extends WalletError {}

/**
 * 同一当前所有者对同一审批重复加签。
 * 签名格式错误、摘要不符或签名者不是当前所有者用 InvalidApprovalSignatureError。
 */
export class DuplicateApprovalSignatureError extends WalletError {}

/** 加签内容不合法：不是 65 字节签名、恢复失败、摘要不匹配，或签名者不是当前所有者 */
export class InvalidApprovalSignatureError extends WalletError {}

/** 审批已过截止时间（过期优先于版本漂移判定） */
export class ApprovalExpiredError extends WalletError {}

/** 审批绑定的策略版本已漂移（加签 / 提交时当前版本不同于创建时版本） */
export class ApprovalPolicyConflictError extends WalletError {}

/** 审批已提交入队，不可再加签或重复提交 */
export class ApprovalAlreadySubmittedError extends WalletError {}

/** 提交时去重后的当前所有者签名数仍未达到当前确认数 */
export class ApprovalThresholdNotMetError extends WalletError {}

/** 提交时审批预留 nonce 已不等于 expectedNonce（被其他提交插队消费） */
export class ApprovalNonceConflictError extends WalletError {
  readonly approvalNonce: bigint;
  readonly expectedNonce: bigint;
  constructor(approvalNonce: bigint, expectedNonce: bigint) {
    super(
      `approval nonce ${approvalNonce} no longer matches expected nonce ${expectedNonce}`,
    );
    this.approvalNonce = approvalNonce;
    this.expectedNonce = expectedNonce;
  }
}
