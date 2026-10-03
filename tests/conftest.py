import pytest

from safewallet import Wallet, address_of_private, sign

# Deterministic owner keys for reproducible tests.
PRIVKEYS = list(range(1, 11))
ADDRESSES = [address_of_private(k) for k in PRIVKEYS]

NOW = 1_000_000
FAR_FUTURE = NOW + 10_000


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


def make_wallet(clock, n_owners=3, threshold=2, wallet_id="wallet-1"):
    return Wallet(
        wallet_id,
        ADDRESSES[:n_owners],
        threshold,
        now=clock,
    )


def signers(privkeys, digest):
    return [sign(k, digest) for k in privkeys]


@pytest.fixture
def wallet(clock):
    return make_wallet(clock)
