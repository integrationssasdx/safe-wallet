/**
 * 执行队列：FIFO 排序、仅队首可执行、终态不可逆、执行幂等。
 *
 * 队列本身不关心任务内容：准入校验由钱包引擎完成；执行语义由执行器回调提供。
 * 任务 id 由入队序号与任务摘要派生，保证同一引擎内可复现、可引用。
 *
 * 任务四态：queued（待执行）与 executed / failed / cancelled 三个终态。
 * cancelled 由所有者取消流程写入（不要求任务在队首，也不调整队列顺序）；
 * executeNext 会越过队首连续的 cancelled（及其他终态）任务，执行首个 queued 任务。
 */

import { createHash } from 'node:crypto';
import {
  InvalidQueueStateError,
  TaskCancellationConflict,
  TaskNotFoundError,
} from './errors.ts';

export type TaskStatus = 'queued' | 'executed' | 'failed' | 'cancelled';

export interface QueueTask<P = unknown> {
  id: string;
  /** 入队序号，从 0 起严格递增；同时决定执行顺序 */
  seq: number;
  nonce: bigint;
  status: TaskStatus;
  submittedAt: bigint;
  /** 签名摘要（域分隔），作为队列层面的防重指纹 */
  digest: string;
  payload: P;
  receipt?: ExecutionReceipt;
}

/** 取消终态专属记录：取消请求自身的 nonce、取消摘要与取消时间 */
export interface CancellationInfo {
  /** 取消请求的 nonce（区别于目标任务的 nonce） */
  nonce: bigint;
  /** 取消摘要（safe-wallet/cancel/v1 域），hex */
  digest: string;
  cancelledAt: bigint;
}

export interface ExecutionReceipt {
  status: Extract<TaskStatus, 'executed' | 'failed' | 'cancelled'>;
  /** 失败时为错误名称（如 PolicyConflict / RequestExpired），成功/取消时为 null */
  failureReason: string | null;
  failureMessage: string | null;
  /** executed/failed 为执行时间；cancelled 为取消时间 */
  executedAt: bigint;
  /** 成功执行的输出（执行器回调返回） */
  result?: unknown;
  /** 仅终态为 cancelled 时存在 */
  cancellation?: CancellationInfo;
}

/**
 * 执行器：对队首任务做实际生效处理。
 * 抛错 → 任务进入 failed 终态（错误名称写入回执）；正常返回 → executed 终态。
 */
export type Executor<P> = (task: QueueTask<P>) => unknown;

export class ExecutionQueue<P = unknown> {
  private readonly tasks: QueueTask<P>[] = [];
  private head = 0;
  private readonly executor: Executor<P>;

  constructor(executor: Executor<P>) {
    this.executor = executor;
  }

  /**
   * 入队（FIFO 尾部）。
   * digest 是任务内容的唯一承诺：在全部历史任务（含失败终态）上都不得重复。
   * 失败任务的 nonce 已被消费，其摘要重现本就会被上层 nonce 防护拦截，这里再兜一层，
   * 保证队列层面的严格防重。
   */
  enqueue(input: { nonce: bigint; digest: string; payload: P; submittedAt: bigint }): QueueTask<P> {
    if (this.tasks.some((t) => t.digest === input.digest)) {
      throw new InvalidQueueStateError(`duplicate task digest: ${input.digest}`);
    }
    const seq = this.tasks.length;
    const task: QueueTask<P> = {
      id: createHash('sha256').update(`${seq}:${input.digest}`).digest('hex').slice(0, 16),
      seq,
      nonce: input.nonce,
      status: 'queued',
      submittedAt: input.submittedAt,
      digest: input.digest,
      payload: input.payload,
    };
    this.tasks.push(task);
    return task;
  }

  /**
   * 队首任务：游标所指的第一个 queued 任务。
   * 游标落在 cancelled 等终态任务上时惰性越过（不调整任务顺序）；
   * 队列空或剩余任务全为终态时为 null。
   */
  peekHead(): QueueTask<P> | null {
    this.skipTerminal();
    return this.head < this.tasks.length ? (this.tasks[this.head] ?? null) : null;
  }

  /** 越过游标处连续的终态任务（cancelled 不随执行推进游标，需由此统一越过） */
  private skipTerminal(): void {
    while (this.head < this.tasks.length && this.tasks[this.head]!.status !== 'queued') {
      this.head += 1;
    }
  }

  /**
   * 执行指定任务。
   * - 仅队首的 queued 任务可执行（保证排序/nonce 语义）；
   * - 终态任务（含 cancelled）重复调用直接返回既有回执，不重复生效（幂等）；
   * - 不存在的 id 抛 TaskNotFoundError；非队首的待执行任务抛 InvalidQueueStateError。
   */
  execute(id: string, now: bigint): QueueTask<P> {
    const task = this.tasks.find((t) => t.id === id);
    if (task === undefined) throw new TaskNotFoundError(`task not found: ${id}`);
    if (task.status !== 'queued') return task; // 幂等：回放终态回执
    this.skipTerminal();
    if (task.seq !== this.head) {
      throw new InvalidQueueStateError(`task ${id} is not at queue head`);
    }

    try {
      const result = this.executor(task);
      task.receipt = { status: 'executed', failureReason: null, failureMessage: null, executedAt: now, result };
      task.status = 'executed';
    } catch (err) {
      const e = err as Error;
      task.receipt = { status: 'failed', failureReason: e.name, failureMessage: e.message, executedAt: now };
      task.status = 'failed';
    }
    this.head += 1;
    return task;
  }

  /**
   * 取消一个 queued 任务，令其进入 cancelled 终态。
   * - 不要求任务在队首，也不调整队列顺序（游标在 executeNext 时自然越过）；
   * - 不调用执行器：目标效果绝不执行；payload / digest / nonce 原样保留；
   * - 目标不存在抛 TaskNotFoundError；已是 executed/failed/cancelled 抛 TaskCancellationConflict。
   */
  cancel(id: string, info: CancellationInfo, now: bigint): QueueTask<P> {
    const task = this.tasks.find((t) => t.id === id);
    if (task === undefined) throw new TaskNotFoundError(`task not found: ${id}`);
    if (task.status !== 'queued') {
      throw new TaskCancellationConflict(`task ${id} is already in terminal state ${task.status}`);
    }
    task.status = 'cancelled';
    task.receipt = {
      status: 'cancelled',
      failureReason: null,
      failureMessage: null,
      executedAt: now,
      cancellation: { nonce: info.nonce, digest: info.digest, cancelledAt: now },
    };
    return task;
  }

  /**
   * 执行当前首个 queued 任务：越过队首或连续的终态任务（典型为 cancelled），
   * 不调整任务本身的顺序。剩余全是终态（或队列空）时返回 null。
   */
  executeNext(now: bigint): QueueTask<P> | null {
    this.skipTerminal();
    if (this.head >= this.tasks.length) return null;
    return this.execute(this.tasks[this.head]!.id, now);
  }

  getTask(id: string): QueueTask<P> | null {
    return this.tasks.find((t) => t.id === id) ?? null;
  }

  /** 队列快照（按入队顺序），任务在执行前后均可见 */
  listTasks(): readonly QueueTask<P>[] {
    return this.tasks;
  }

  get size(): number {
    return this.tasks.length;
  }
}
