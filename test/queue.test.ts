import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ExecutionQueue } from '../src/queue.ts';
import {
  InvalidQueueStateError,
  PolicyConflict,
  TaskCancellationConflict,
  TaskNotFoundError,
} from '../src/errors.ts';

function makeQueue(exec?: (t: any) => unknown) {
  const calls: string[] = [];
  const queue = new ExecutionQueue<any>(
    exec ??
      ((t) => {
        calls.push(t.id);
        return { ok: true, id: t.id };
      }),
  );
  return { queue, calls };
}

function enq(queue: ExecutionQueue<any>, seq: number, digest?: string) {
  return queue.enqueue({
    nonce: BigInt(seq),
    digest: digest ?? `d-${seq}`,
    payload: { seq },
    submittedAt: 1000n,
  });
}

test('FIFO：按入队顺序排列，队首优先执行', () => {
  const { queue, calls } = makeQueue();
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  const c = enq(queue, 2);
  assert.deepEqual(queue.listTasks().map((t) => t.seq), [0, 1, 2]);

  assert.equal(queue.peekHead()!.id, a.id);
  queue.executeNext(1n);
  assert.equal(calls[0], a.id);
  queue.executeNext(1n);
  assert.equal(calls[1], b.id);
  queue.executeNext(1n);
  assert.equal(calls[2], c.id);
  assert.equal(queue.executeNext(1n), null);
});

test('只能执行队首：跳过队首直接执行后续任务报错', () => {
  const { queue } = makeQueue();
  enq(queue, 0);
  const second = enq(queue, 1);
  assert.throws(() => queue.execute(second.id, 1n), InvalidQueueStateError);
});

test('终态不可逆：执行器对终态任务不再被调用', () => {
  let count = 0;
  const queue = new ExecutionQueue<any>(() => {
    count++;
    return { count };
  });
  const a = enq(queue, 0);
  enq(queue, 1);
  const done = queue.execute(a.id, 1n);
  assert.equal(done.status, 'executed');
  // 幂等：重复执行同一终态任务，直接返回既有回执
  const again = queue.execute(a.id, 2n);
  assert.equal(again, done);
  assert.equal(count, 1);
  assert.equal(again.receipt!.executedAt, 1n);
});

test('执行器抛错 → 任务 failed 终态并记录原因；队首推进', () => {
  const queue = new ExecutionQueue<any>(() => {
    throw new PolicyConflict('drift');
  });
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  const r = queue.executeNext(1n);
  assert.equal(r!.status, 'failed');
  assert.equal(r!.receipt!.failureReason, 'PolicyConflict');
  assert.equal(r!.receipt!.failureMessage, 'drift');
  // 失败也是终态：重复执行不重放
  assert.equal(queue.execute(a.id, 2n), r);
  // 队首已推进，后续任务可执行
  assert.equal(queue.execute(b.id, 3n).status, 'failed');
});

test('不存在的任务 id → TaskNotFoundError', () => {
  const { queue } = makeQueue();
  assert.throws(() => queue.execute('nope', 1n), TaskNotFoundError);
  assert.equal(queue.getTask('nope'), null);
});

test('队列防重：非失败任务的相同 digest 不能重复入队', () => {
  const { queue } = makeQueue();
  enq(queue, 0, 'same');
  assert.throws(() => enq(queue, 1, 'same'), InvalidQueueStateError);
});

test('任务入队后即在队列快照可见（执行前后均可见）', () => {
  const { queue } = makeQueue();
  const a = enq(queue, 0);
  assert.equal(queue.listTasks().length, 1);
  assert.equal(queue.getTask(a.id)!.status, 'queued');
  queue.executeNext(1n);
  assert.equal(queue.listTasks().length, 1);
  assert.equal(queue.getTask(a.id)!.status, 'executed');
});

test('入队序号与 id 稳定且唯一', () => {
  const { queue } = makeQueue();
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  assert.notEqual(a.id, b.id);
  assert.equal(a.seq, 0);
  assert.equal(b.seq, 1);
});

// ---------- 任务取消 ----------

test('取消 queued 任务 → cancelled 终态，不调用执行器，原 payload/digest/nonce 保留', () => {
  const { queue, calls } = makeQueue();
  const a = enq(queue, 0);
  const r = queue.cancel(a.id, { nonce: 9n, digest: 'cancel-digest', cancelledAt: 5n }, 5n);
  assert.equal(r.status, 'cancelled');
  assert.equal(r.payload.seq, 0);
  assert.equal(r.digest, 'd-0');
  assert.equal(r.nonce, 0n);
  assert.deepEqual(calls, []); // 目标效果绝不执行
  const info = r.receipt!.cancellation!;
  assert.equal(info.nonce, 9n);
  assert.equal(info.digest, 'cancel-digest');
  assert.equal(info.cancelledAt, 5n);
  assert.equal(r.receipt!.executedAt, 5n);
  assert.equal(r.receipt!.failureReason, null);
});

test('取消不要求队首，也不调整队列顺序', () => {
  const { queue } = makeQueue();
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  const c = enq(queue, 2);
  queue.cancel(b.id, { nonce: 9n, digest: 'x', cancelledAt: 1n }, 1n);
  assert.deepEqual(queue.listTasks().map((t) => t.seq), [0, 1, 2]);
  assert.equal(queue.peekHead()!.id, a.id); // 队首仍是 a
  assert.equal(queue.getTask(c.id)!.status, 'queued');
});

test('executeNext 越过队首/连续 cancelled，执行首个 queued；全为终态返回 null', () => {
  const { queue, calls } = makeQueue();
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  const c = enq(queue, 2);
  queue.cancel(a.id, { nonce: 9n, digest: 'x', cancelledAt: 1n }, 1n);
  queue.cancel(b.id, { nonce: 10n, digest: 'y', cancelledAt: 1n }, 1n);
  assert.equal(queue.executeNext(2n)!.id, c.id);
  assert.deepEqual(calls, [c.id]);
  assert.equal(queue.executeNext(3n), null);
});

test('executeTask 对 cancelled 任务直接返回终态（幂等），不调用执行器', () => {
  const { queue, calls } = makeQueue();
  const a = enq(queue, 0);
  const cancelled = queue.cancel(a.id, { nonce: 9n, digest: 'x', cancelledAt: 1n }, 1n);
  assert.equal(queue.execute(a.id, 2n), cancelled);
  assert.deepEqual(calls, []);
});

test('取消不存在的 id → TaskNotFoundError；取消 executed/failed/cancelled → TaskCancellationConflict', () => {
  const queue = new ExecutionQueue<any>(() => {
    throw new PolicyConflict('drift');
  });
  const a = enq(queue, 0);
  const b = enq(queue, 1);
  const c = enq(queue, 2);
  assert.throws(() => queue.cancel('nope', { nonce: 9n, digest: 'x', cancelledAt: 1n }, 1n), TaskNotFoundError);

  // 独立队列取一个 executed 样本
  const q2 = new ExecutionQueue<any>(() => ({ ok: 1 }));
  const e = q2.enqueue({ nonce: 0n, digest: 'e', payload: {}, submittedAt: 1n });
  q2.executeNext(1n);
  assert.throws(() => q2.cancel(e.id, { nonce: 9n, digest: 'x', cancelledAt: 2n }, 2n), TaskCancellationConflict);

  queue.executeNext(1n); // a → failed（执行器恒抛 PolicyConflict）
  assert.equal(queue.getTask(a.id)!.status, 'failed');
  assert.throws(() => queue.cancel(a.id, { nonce: 9n, digest: 'x', cancelledAt: 2n }, 2n), TaskCancellationConflict);

  queue.cancel(b.id, { nonce: 9n, digest: 'x', cancelledAt: 2n }, 2n);
  assert.throws(() => queue.cancel(b.id, { nonce: 10n, digest: 'y', cancelledAt: 3n }, 3n), TaskCancellationConflict);

  // c 仍 queued，不受影响
  assert.equal(queue.getTask(c.id)!.status, 'queued');
});
