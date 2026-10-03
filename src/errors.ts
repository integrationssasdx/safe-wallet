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
