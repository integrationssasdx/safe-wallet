/**
 * 引擎公开错误类型。
 *
 * 设计约定：
 * - 提交阶段（普通交易 / 策略变更）对“内容不合法”的判定互不混用：
 *   普通交易 → InvalidTransaction；策略变更 → InvalidPolicyChange。
 * - RequestExpired 仅用于截止时间已过；PolicyConflict 仅用于执行时版本已漂移。
 * - NonceAlreadyUsedError 是既有重放防护的公开异常，策略变更沿用同一类型。
 * - 任务取消：内容/签名不合法 → InvalidCancellation；目标已是终态 → TaskCancellationConflict。
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

/**
 * 任务取消请求不合法：字段非法、摘要与提交内容不一致、签名不可恢复/不规范、
 * 签名者非当前所有者、去重后有效签名不足确认数。
 * 除成功取消外，抛出本错误不改变任务、不消费 nonce、不修改钱包策略。
 */
export class InvalidCancellation extends WalletError {}

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

/** 对不存在任务、终态任务重复执行等队列层面的非法操作 */
export class TaskNotFoundError extends WalletError {}

export class InvalidQueueStateError extends WalletError {}

/**
 * 取消冲突：目标任务已是 executed / failed / cancelled 终态，不能再取消。
 * （目标不存在仍抛 TaskNotFoundError；本错误不消费本次取消 nonce。）
 */
export class TaskCancellationConflict extends WalletError {}
