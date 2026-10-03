"""Policy-change tasks: owners use the current threshold signature to add or
remove owners and adjust the confirmation count."""

import pytest

from safewallet import (
    EXECUTED,
    FAILED,
    PENDING,
    InvalidPolicyChange,
    InvalidTransaction,
    NonceAlreadyUsed,
    PolicyConflict,
    RequestExpired,
)
from safewallet.crypto import ZERO_ADDRESS

from conftest import ADDRESSES, FAR_FUTURE, NOW, PRIVKEYS, make_wallet, signers

NEW_OWNERS = ADDRESSES[2:5]  # drop owner 0/1, keep 2, add 3 and 4


def change(wallet, new_owners=NEW_OWNERS, new_threshold=2, version=0, nonce=0,
           deadline=FAR_FUTURE, keys=PRIVKEYS[:2]):
    try:
        digest = wallet.policy_change_digest(new_owners, new_threshold, version,
                                             nonce, deadline)
    except TypeError:
        digest = b"\x00" * 32  # unencodable field: signature check is never reached
    return wallet.submit_policy_change(
        new_owners, new_threshold, version, nonce, deadline, signers(keys, digest)
    )


class TestHappyPath:
    def test_submit_queues_pending_task(self, wallet):
        task = change(wallet)
        assert task.status == PENDING
        assert wallet.pending_tasks() == [task]
        assert wallet.next_nonce == 1
        # Policy untouched until execution.
        assert wallet.owners == tuple(ADDRESSES[:3])
        assert wallet.threshold == 2
        assert wallet.version == 0

    def test_execute_swaps_policy_and_bumps_version(self, wallet):
        task = change(wallet)
        wallet.execute(task.task_id)
        assert task.status == EXECUTED
        assert wallet.owners == tuple(NEW_OWNERS)
        assert wallet.threshold == 2
        assert wallet.version == 1

    def test_execute_next_follows_queue_order(self, wallet):
        digest = wallet.transfer_digest("0x" + "ab" * 20, 5, 0, FAR_FUTURE)
        first = wallet.submit_transfer("0x" + "ab" * 20, 5, 0, FAR_FUTURE,
                                       signers(PRIVKEYS[:2], digest))
        second = change(wallet, nonce=1)
        assert wallet.execute_next() is first
        assert wallet.execute_next() is second
        assert wallet.version == 1

    def test_new_policy_governs_next_requests(self, wallet):
        task = change(wallet, new_threshold=3)
        wallet.execute(task.task_id)
        # Old owner set can no longer reach the new threshold of 3.
        digest = wallet.transfer_digest("0x" + "ab" * 20, 5, 1, FAR_FUTURE)
        with pytest.raises(InvalidTransaction):
            wallet.submit_transfer("0x" + "ab" * 20, 5, 1, FAR_FUTURE,
                                   signers(PRIVKEYS[:2], digest))
        # The new owners can, and regular transfers still carry no version field.
        sigs = signers(PRIVKEYS[2:5], digest)
        t = wallet.submit_transfer("0x" + "ab" * 20, 5, 1, FAR_FUTURE, sigs)
        wallet.execute(t.task_id)
        assert t.status == EXECUTED

    def test_old_requests_cannot_reapply_after_execution(self, wallet):
        task = change(wallet)
        wallet.execute(task.task_id)
        # Old nonce is consumed.
        with pytest.raises(NonceAlreadyUsed):
            change(wallet)
        # Old version no longer matches even with a fresh nonce.
        with pytest.raises(InvalidPolicyChange):
            change(wallet, nonce=1)
        # Old signatures bind the old payload: re-signing the old request with
        # the old owners is rejected at the version check.
        assert wallet.owners == tuple(NEW_OWNERS)
        assert wallet.version == 1


class TestSubmissionValidation:
    @pytest.mark.parametrize("owners,threshold", [
        ([], 1),                                  # empty owner list
        ([ADDRESSES[3], ADDRESSES[3]], 1),        # duplicates
        ([ZERO_ADDRESS, ADDRESSES[3]], 1),        # zero address
        ([ADDRESSES[3]], 0),                      # threshold zero
        ([ADDRESSES[3]], -1),                     # threshold negative
        ([ADDRESSES[3]], 2),                      # threshold above owner count
    ])
    def test_invalid_policy_fields(self, wallet, owners, threshold):
        with pytest.raises(InvalidPolicyChange):
            change(wallet, new_owners=owners, new_threshold=threshold)
        assert wallet.pending_tasks() == []
        assert wallet.next_nonce == 0
        assert wallet.version == 0

    def test_version_mismatch(self, wallet):
        with pytest.raises(InvalidPolicyChange):
            change(wallet, version=1)
        with pytest.raises(InvalidPolicyChange):
            change(wallet, version=-1)

    def test_out_of_order_nonce(self, wallet):
        with pytest.raises(InvalidPolicyChange):
            change(wallet, nonce=1)

    def test_used_nonce_uses_existing_replay_error(self, wallet):
        change(wallet)
        with pytest.raises(NonceAlreadyUsed):
            change(wallet, new_owners=ADDRESSES[3:6])

    def test_expired_deadline(self, wallet):
        with pytest.raises(RequestExpired):
            change(wallet, deadline=NOW - 1)

    def test_insufficient_signatures(self, wallet):
        digest = wallet.policy_change_digest(NEW_OWNERS, 2, 0, 0, FAR_FUTURE)
        with pytest.raises(InvalidPolicyChange):
            wallet.submit_policy_change(NEW_OWNERS, 2, 0, 0, FAR_FUTURE,
                                        signers(PRIVKEYS[:1], digest))

    def test_duplicate_signatures_count_once(self, wallet):
        digest = wallet.policy_change_digest(NEW_OWNERS, 2, 0, 0, FAR_FUTURE)
        sig = signers(PRIVKEYS[:1], digest)[0]
        with pytest.raises(InvalidPolicyChange):
            wallet.submit_policy_change(NEW_OWNERS, 2, 0, 0, FAR_FUTURE, [sig, sig])

    def test_non_owner_signature(self, wallet):
        digest = wallet.policy_change_digest(NEW_OWNERS, 2, 0, 0, FAR_FUTURE)
        sigs = signers([PRIVKEYS[0], PRIVKEYS[9]], digest)
        with pytest.raises(InvalidPolicyChange):
            wallet.submit_policy_change(NEW_OWNERS, 2, 0, 0, FAR_FUTURE, sigs)

    @pytest.mark.parametrize("field", ["owners", "threshold", "version", "nonce",
                                       "deadline", "wallet"])
    def test_payload_mismatch(self, wallet, field):
        # Sign a payload that differs in exactly one bound field from the
        # submission; the recovered signers must not authorize the request.
        sign_kwargs = dict(new_owners=NEW_OWNERS, new_threshold=2, version=0,
                           nonce=0, deadline=FAR_FUTURE)
        if field == "owners":
            sign_kwargs["new_owners"] = ADDRESSES[3:6]
        elif field == "threshold":
            sign_kwargs["new_threshold"] = 1
        elif field == "version":
            sign_kwargs["version"] = 7
        elif field == "nonce":
            sign_kwargs["nonce"] = 9
        elif field == "deadline":
            sign_kwargs["deadline"] = FAR_FUTURE + 1
        sign_wallet = wallet
        if field == "wallet":
            sign_wallet = make_wallet(wallet._now, wallet_id="other-wallet")
        digest = sign_wallet.policy_change_digest(**sign_kwargs)
        with pytest.raises(InvalidPolicyChange):
            wallet.submit_policy_change(NEW_OWNERS, 2, 0, 0, FAR_FUTURE,
                                        signers(PRIVKEYS[:2], digest))
        assert wallet.pending_tasks() == []
        assert wallet.next_nonce == 0

    def test_failed_submission_changes_nothing(self, wallet):
        with pytest.raises(InvalidPolicyChange):
            change(wallet, new_owners=[])
        assert wallet.owners == tuple(ADDRESSES[:3])
        assert wallet.threshold == 2
        assert wallet.version == 0
        assert wallet.next_nonce == 0
        assert wallet.tasks() == []


class TestQueueSemantics:
    def test_identical_resubmit_is_idempotent(self, wallet):
        task = change(wallet)
        again = change(wallet)
        assert again is task
        assert len(wallet.tasks()) == 1
        assert wallet.next_nonce == 1

    def test_policy_change_visible_and_ordered_in_queue(self, wallet):
        t0 = change(wallet, nonce=0)
        digest = wallet.transfer_digest("0x" + "ab" * 20, 5, 1, FAR_FUTURE)
        t1 = wallet.submit_transfer("0x" + "ab" * 20, 5, 1, FAR_FUTURE,
                                    signers(PRIVKEYS[:2], digest))
        assert wallet.tasks() == [t0, t1]
        assert wallet.pending_tasks() == [t0, t1]


class TestExecutionConflict:
    def test_stale_version_fails_with_policy_conflict(self, wallet):
        first = change(wallet, nonce=0)
        second = change(wallet, new_owners=ADDRESSES[3:6], new_threshold=2, nonce=1)
        wallet.execute(first.task_id)
        assert wallet.version == 1
        with pytest.raises(PolicyConflict):
            wallet.execute(second.task_id)
        assert second.status == FAILED
        assert second.error == "PolicyConflict"
        # Policy keeps the first task's values, not the second's.
        assert wallet.owners == tuple(NEW_OWNERS)
        assert wallet.version == 1

    def test_failed_task_is_terminal(self, wallet):
        first = change(wallet, nonce=0)
        second = change(wallet, new_owners=ADDRESSES[3:6], nonce=1)
        wallet.execute(first.task_id)
        with pytest.raises(PolicyConflict):
            wallet.execute(second.task_id)
        again = wallet.execute(second.task_id)  # idempotent, stays failed
        assert again.status == FAILED
        assert wallet.version == 1

    def test_resubmit_of_failed_task_hits_replay_protection(self, wallet):
        first = change(wallet, nonce=0)
        second = change(wallet, new_owners=ADDRESSES[3:6], nonce=1)
        wallet.execute(first.task_id)
        with pytest.raises(PolicyConflict):
            wallet.execute(second.task_id)
        with pytest.raises(NonceAlreadyUsed):
            change(wallet, new_owners=ADDRESSES[3:6], nonce=1)

    def test_transfers_unaffected_by_policy_change_flow(self, wallet):
        # A transfer queued before the change still executes with its own
        # (version-free) payload after the policy was replaced.
        digest = wallet.transfer_digest("0x" + "ab" * 20, 5, 0, FAR_FUTURE)
        transfer_task = wallet.submit_transfer("0x" + "ab" * 20, 5, 0, FAR_FUTURE,
                                               signers(PRIVKEYS[:2], digest))
        change_task = change(wallet, nonce=1)
        wallet.execute(change_task.task_id)
        wallet.execute(transfer_task.task_id)
        assert transfer_task.status == EXECUTED
        assert wallet.transfer_log == [{"to": "0x" + "ab" * 20, "amount": 5}]
