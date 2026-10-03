"""Baseline behavior: threshold policy, signature collection, replay
protection and the execution queue for regular transfers."""

import pytest

from safewallet import (
    EXECUTED,
    FAILED,
    PENDING,
    InvalidTransaction,
    NonceAlreadyUsed,
    RequestExpired,
)
from safewallet.crypto import ZERO_ADDRESS

from conftest import ADDRESSES, FAR_FUTURE, NOW, PRIVKEYS, make_wallet, signers


def transfer(wallet, nonce=0, to="0x" + "ab" * 20, amount=100, deadline=FAR_FUTURE,
             keys=PRIVKEYS[:2]):
    try:
        digest = wallet.transfer_digest(to, amount, nonce, deadline)
    except TypeError:
        digest = b"\x00" * 32  # unencodable field: signature check is never reached
    return wallet.submit_transfer(to, amount, nonce, deadline, signers(keys, digest))


class TestTransferFlow:
    def test_submit_queues_pending_task(self, wallet):
        task = transfer(wallet)
        assert task.status == PENDING
        assert wallet.pending_tasks() == [task]
        assert wallet.next_nonce == 1

    def test_execute_records_result(self, wallet):
        task = transfer(wallet)
        wallet.execute(task.task_id)
        assert task.status == EXECUTED
        assert wallet.transfer_log == [{"to": "0x" + "ab" * 20, "amount": 100}]

    def test_queue_is_fifo(self, wallet):
        t0 = transfer(wallet, nonce=0, amount=1)
        t1 = transfer(wallet, nonce=1, amount=2)
        t2 = transfer(wallet, nonce=2, amount=3)
        assert [t.task_id for t in wallet.tasks()] == [t0.task_id, t1.task_id, t2.task_id]
        assert wallet.execute_next() is t0
        assert wallet.execute_next() is t1
        assert wallet.execute_next() is t2
        assert wallet.execute_next() is None

    def test_execute_is_idempotent_on_terminal_task(self, wallet):
        task = transfer(wallet)
        wallet.execute(task.task_id)
        again = wallet.execute(task.task_id)
        assert again.status == EXECUTED
        assert len(wallet.transfer_log) == 1


class TestTransferValidation:
    def test_insufficient_signatures(self, wallet):
        digest = wallet.transfer_digest("0x" + "ab" * 20, 100, 0, FAR_FUTURE)
        with pytest.raises(InvalidTransaction):
            wallet.submit_transfer("0x" + "ab" * 20, 100, 0, FAR_FUTURE,
                                   signers(PRIVKEYS[:1], digest))
        assert wallet.pending_tasks() == []
        assert wallet.next_nonce == 0

    def test_duplicate_signatures_count_once(self, wallet):
        digest = wallet.transfer_digest("0x" + "ab" * 20, 100, 0, FAR_FUTURE)
        sig = signers(PRIVKEYS[:1], digest)[0]
        with pytest.raises(InvalidTransaction):
            wallet.submit_transfer("0x" + "ab" * 20, 100, 0, FAR_FUTURE, [sig, sig])

    def test_non_owner_signature_rejected(self, wallet):
        digest = wallet.transfer_digest("0x" + "ab" * 20, 100, 0, FAR_FUTURE)
        sigs = signers([PRIVKEYS[0], PRIVKEYS[9]], digest)
        with pytest.raises(InvalidTransaction):
            wallet.submit_transfer("0x" + "ab" * 20, 100, 0, FAR_FUTURE, sigs)

    def test_used_nonce_raises_replay_error(self, wallet):
        transfer(wallet, nonce=0)
        with pytest.raises(NonceAlreadyUsed):
            transfer(wallet, nonce=0, amount=999)

    def test_out_of_order_nonce(self, wallet):
        with pytest.raises(InvalidTransaction):
            transfer(wallet, nonce=1)

    def test_expired_deadline(self, wallet, clock):
        with pytest.raises(RequestExpired):
            transfer(wallet, deadline=NOW - 1)

    def test_bad_fields(self, wallet):
        with pytest.raises(InvalidTransaction):
            transfer(wallet, to=ZERO_ADDRESS)
        with pytest.raises(InvalidTransaction):
            transfer(wallet, amount=0)
        with pytest.raises(InvalidTransaction):
            transfer(wallet, amount=-5)


class TestQueueIdempotency:
    def test_identical_resubmit_returns_same_task(self, wallet):
        task = transfer(wallet)
        again = transfer(wallet)
        assert again is task
        assert len(wallet.tasks()) == 1
        assert wallet.next_nonce == 1

    def test_resubmit_after_execution_hits_replay_protection(self, wallet):
        task = transfer(wallet)
        wallet.execute(task.task_id)
        with pytest.raises(NonceAlreadyUsed):
            transfer(wallet)

    def test_executed_task_is_terminal(self, wallet):
        task = transfer(wallet)
        wallet.execute(task.task_id)
        assert task.is_terminal
        assert task.status == EXECUTED
