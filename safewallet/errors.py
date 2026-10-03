"""Public exception hierarchy of the wallet policy engine."""


class WalletError(Exception):
    """Base class for all engine errors."""


class RequestExpired(WalletError):
    """The request deadline is earlier than the current time."""


class NonceAlreadyUsed(WalletError):
    """Replay protection: the nonce has already been consumed."""


class InvalidTransaction(WalletError):
    """A regular transaction failed validation (fields, nonce order, signatures)."""


class InvalidPolicyChange(WalletError):
    """A policy-change request failed validation.

    Raised for any of: invalid new policy fields, insufficient threshold
    signatures, signature payload mismatch, policy version mismatch, or
    incorrect nonce order. No task is created, no nonce is consumed and
    the current policy is left untouched.
    """


class PolicyConflict(WalletError):
    """At execution time the bound policy version no longer matches.

    The task moves to the failed terminal state and the policy is unchanged.
    """


class UnknownTask(WalletError):
    """No task exists for the given task id."""
