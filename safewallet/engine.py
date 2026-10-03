"""Multisig wallet policy engine.

Threshold policy, signature collection, replay protection and an execution
queue, plus policy-change tasks decided by the current threshold signature.

Regular transactions keep the classic flow — collect signatures off-chain,
submit, enter the queue, execute — and never carry a policy version field.
Policy changes are submitted with the *current* policy version bound into
the signature payload and only take effect if that version is still current
when the task executes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from . import crypto
from .crypto import ZERO_ADDRESS, payload_digest
from .errors import (
    InvalidPolicyChange,
    InvalidTransaction,
    NonceAlreadyUsed,
    PolicyConflict,
    RequestExpired,
    UnknownTask,
)

TRANSFER_OP = "TRANSFER"
POLICY_CHANGE_OP = "POLICY_CHANGE"

# Task statuses.
PENDING = "pending"
EXECUTED = "executed"
FAILED = "failed"
TERMINAL_STATUSES = frozenset({EXECUTED, FAILED})


@dataclass
class Task:
    """A queued unit of work produced by a validated submission."""

    task_id: str
    kind: str  # TRANSFER_OP or POLICY_CHANGE_OP
    seq: int
    payload: dict
    status: str = PENDING
    error: Optional[str] = None
    result: Optional[dict] = None

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES


@dataclass
class Policy:
    owners: tuple[str, ...]
    threshold: int
    version: int = 0


def _validate_owner_set(owners: Iterable[str], threshold: int, error_cls) -> tuple[str, ...]:
    owners = tuple(owners)
    if not owners:
        raise error_cls("owner list must not be empty")
    if len(set(owners)) != len(owners):
        raise error_cls("owner list contains duplicates")
    if any(o == ZERO_ADDRESS for o in owners):
        raise error_cls("owner list contains the zero address")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise error_cls("threshold must be an integer")
    if threshold <= 0:
        raise error_cls("threshold must be greater than zero")
    if threshold > len(owners):
        raise error_cls("threshold must not exceed the owner count")
    return owners


class Wallet:
    """A multisig wallet with a threshold policy and an execution queue."""

    def __init__(
        self,
        wallet_id: str,
        owners: Iterable[str],
        threshold: int,
        now: Callable[[], float] = time.time,
    ):
        self.wallet_id = wallet_id
        initial = _validate_owner_set(owners, threshold, InvalidTransaction)
        self._policy = Policy(owners=initial, threshold=threshold, version=0)
        self._now = now
        self.next_nonce = 0
        self._tasks: dict[str, Task] = {}
        self._order: list[str] = []
        self._dedup: dict[bytes, str] = {}
        self.transfer_log: list[dict] = []

    # --- read-only views ---------------------------------------------------

    @property
    def owners(self) -> tuple[str, ...]:
        return self._policy.owners

    @property
    def threshold(self) -> int:
        return self._policy.threshold

    @property
    def version(self) -> int:
        return self._policy.version

    def get_task(self, task_id: str) -> Task:
        try:
            return self._tasks[task_id]
        except KeyError:
            raise UnknownTask(task_id) from None

    def tasks(self) -> list[Task]:
        """All tasks in queue (submission) order."""
        return [self._tasks[tid] for tid in self._order]

    def pending_tasks(self) -> list[Task]:
        return [t for t in self.tasks() if t.status == PENDING]

    # --- signature payloads -------------------------------------------------

    def transfer_digest(self, to: str, amount: int, nonce: int, deadline: int) -> bytes:
        """Payload owners sign for a regular transfer. No policy version field."""
        return payload_digest(TRANSFER_OP, self.wallet_id, to, amount, nonce, deadline)

    def policy_change_digest(
        self,
        new_owners: Iterable[str],
        new_threshold: int,
        version: int,
        nonce: int,
        deadline: int,
    ) -> bytes:
        """Payload owners sign for a policy change.

        Binds the wallet id, the operation, the *current* policy version,
        the new owners, the new threshold, the nonce and the deadline.
        """
        return payload_digest(
            POLICY_CHANGE_OP,
            self.wallet_id,
            version,
            list(new_owners),
            new_threshold,
            nonce,
            deadline,
        )

    # --- shared validation helpers ------------------------------------------

    def _check_nonce(self, nonce: int, error_cls) -> None:
        if nonce < self.next_nonce:
            raise NonceAlreadyUsed(f"nonce {nonce} already used")
        if nonce != self.next_nonce:
            raise error_cls(f"nonce out of order: expected {self.next_nonce}")

    @staticmethod
    def _check_int(value, name: str, error_cls) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise error_cls(f"{name} must be a non-negative integer")

    def _check_deadline(self, deadline: int) -> None:
        if deadline < self._now():
            raise RequestExpired(f"deadline {deadline} is in the past")

    def _verify_threshold(self, digest: bytes, signatures, error_cls) -> None:
        signers: set[str] = set()
        for sig in signatures:
            try:
                signer = crypto.recover_address(digest, sig)
            except (ValueError, TypeError):
                raise error_cls("malformed signature") from None
            if signer not in self._policy.owners:
                raise error_cls(f"signer {signer} is not an owner")
            signers.add(signer)  # duplicate signatures count once
        if len(signers) < self._policy.threshold:
            raise error_cls(
                f"threshold not met: {len(signers)} of {self._policy.threshold}"
            )

    # --- queue internals ------------------------------------------------------

    def _dedup_lookup(self, key: bytes) -> Optional[Task]:
        task_id = self._dedup.get(key)
        if task_id is None:
            return None
        task = self._tasks[task_id]
        # Idempotency covers live tasks only; resubmitting a terminal task
        # falls through to normal validation (e.g. replay protection).
        return task if not task.is_terminal else None

    def _enqueue(self, kind: str, key: bytes, payload: dict) -> Task:
        task_id = "task-" + key.hex()[:24]
        task = Task(task_id=task_id, kind=kind, seq=len(self._order), payload=payload)
        self._tasks[task_id] = task
        self._order.append(task_id)
        self._dedup[key] = task_id
        self.next_nonce += 1
        return task

    # --- submissions ----------------------------------------------------------

    def submit_transfer(
        self, to: str, amount: int, nonce: int, deadline: int, signatures
    ) -> Task:
        """Validate and queue a regular transfer."""
        self._check_deadline(deadline)
        if to == ZERO_ADDRESS:
            raise InvalidTransaction("cannot transfer to the zero address")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise InvalidTransaction("amount must be a positive integer")
        self._check_int(nonce, "nonce", InvalidTransaction)
        key = payload_digest(TRANSFER_OP, self.wallet_id, to, amount, nonce, deadline)
        existing = self._dedup_lookup(key)
        if existing is not None:
            return existing
        self._check_nonce(nonce, InvalidTransaction)
        self._verify_threshold(
            self.transfer_digest(to, amount, nonce, deadline), signatures, InvalidTransaction
        )
        return self._enqueue(
            TRANSFER_OP, key, {"to": to, "amount": amount, "nonce": nonce, "deadline": deadline}
        )

    def submit_policy_change(
        self,
        new_owners: Iterable[str],
        new_threshold: int,
        version: int,
        nonce: int,
        deadline: int,
        signatures,
    ) -> Task:
        """Validate and queue a policy-change task.

        Any validation failure raises InvalidPolicyChange (or RequestExpired /
        NonceAlreadyUsed) without creating a task, consuming the nonce or
        touching the current policy.
        """
        new_owners = list(new_owners)
        self._check_deadline(deadline)
        checked_owners = _validate_owner_set(new_owners, new_threshold, InvalidPolicyChange)
        self._check_int(version, "version", InvalidPolicyChange)
        self._check_int(nonce, "nonce", InvalidPolicyChange)
        key = payload_digest(
            POLICY_CHANGE_OP,
            self.wallet_id,
            version,
            checked_owners,
            new_threshold,
            nonce,
            deadline,
        )
        existing = self._dedup_lookup(key)
        if existing is not None:
            return existing
        self._check_nonce(nonce, InvalidPolicyChange)
        if version != self._policy.version:
            raise InvalidPolicyChange(
                f"version mismatch: bound {version}, current {self._policy.version}"
            )
        self._verify_threshold(
            self.policy_change_digest(checked_owners, new_threshold, version, nonce, deadline),
            signatures,
            InvalidPolicyChange,
        )
        return self._enqueue(
            POLICY_CHANGE_OP,
            key,
            {
                "new_owners": list(checked_owners),
                "new_threshold": new_threshold,
                "version": version,
                "nonce": nonce,
                "deadline": deadline,
            },
        )

    # --- execution --------------------------------------------------------------

    def execute(self, task_id: str) -> Task:
        """Execute a pending task. Terminal tasks are returned unchanged."""
        task = self.get_task(task_id)
        if task.is_terminal:
            return task
        if task.kind == TRANSFER_OP:
            record = {"to": task.payload["to"], "amount": task.payload["amount"]}
            self.transfer_log.append(record)
            task.result = record
            task.status = EXECUTED
            return task
        # Policy change: only takes effect against the version it was bound to.
        if task.payload["version"] != self._policy.version:
            task.status = FAILED
            task.error = PolicyConflict.__name__
            raise PolicyConflict(
                f"task bound to version {task.payload['version']}, "
                f"current version is {self._policy.version}"
            )
        self._policy = Policy(
            owners=tuple(task.payload["new_owners"]),
            threshold=task.payload["new_threshold"],
            version=self._policy.version + 1,
        )
        task.result = {
            "owners": list(self._policy.owners),
            "threshold": self._policy.threshold,
            "version": self._policy.version,
        }
        task.status = EXECUTED
        return task

    def execute_next(self) -> Optional[Task]:
        """Execute the oldest pending task, or return None if the queue is drained."""
        for task_id in self._order:
            if self._tasks[task_id].status == PENDING:
                return self.execute(task_id)
        return None
