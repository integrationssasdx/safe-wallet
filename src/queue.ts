/**
 * 执行队列：FIFO 排序、仅队首可执行、终态不可逆、执行幂等。
 *
 * 队列本身不关心任务内容：准入校验由钱包引擎完成；执行语义由执行器回调提供。
 * 任务 id 由入队序号与任务摘要派生，保证同一引擎内可复现、可引用。
 */

import { createHash } from 'node:crypto';
import { InvalidQueueStateError, TaskNotFoundError } from './errors.ts';

export type TaskStatus = 'queued' | 'executed' | 'failed';

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

export interface ExecutionReceipt {
  status: Extract<TaskStatus, 'executed' | 'failed'>;
  /** 失败时为错误名称（如 PolicyConflict / RequestExpired），成功时为 null */
  failureReason: string | null;
  failureMessage: string | null;
  executedAt: bigint;
  /** 成功执行的输出（执行器回调返回） */
  result?: unknown;
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

  /** 队首任务；队列空或队首已终态时为 null */
  peekHead(): QueueTask<P> | null {
    return this.head < this.tasks.length ? (this.tasks[this.head] ?? null) : null;
  }

  /**
   * 执行指定任务。
   * - 仅队首可执行（保证排序/nonce 语义）；
   * - 终态任务重复调用直接返回既有回执，不重复生效（幂等）；
   * - 不存在的 id 抛 TaskNotFoundError；非队首的待执行任务抛 InvalidQueueStateError。
   */
  execute(id: string, now: bigint): QueueTask<P> {
    const task = this.tasks.find((t) => t.id === id);
    if (task === undefined) throw new TaskNotFoundError(`task not found: ${id}`);
    if (task.status !== 'queued') return task; // 幂等：回放终态回执
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

  /** 执行当前队首；队列已排空时返回 null */
  executeNext(now: bigint): QueueTask<P> | null {
    const head = this.peekHead();
    if (head === null) return null;
    return this.execute(head.id, now);
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
