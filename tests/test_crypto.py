from safewallet import crypto


def test_sign_recover_roundtrip():
    digest = crypto.payload_digest("OP", "wallet", 1, 2, 3)
    sig = crypto.sign(7, digest)
    assert crypto.recover_address(digest, sig) == crypto.address_of_private(7)


def test_verify_rejects_wrong_digest():
    sig = crypto.sign(7, b"\x01" * 32)
    assert not crypto.verify(crypto.private_to_public(7), b"\x02" * 32, sig)


def test_recover_rejects_malformed_signature():
    digest = b"\x00" * 32
    for bad in [(0, 1, 0), (1, 0, 0), (1, 1, 5), (crypto.N, 1, 0)]:
        try:
            crypto.recover_address(digest, bad)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"accepted malformed signature {bad}")


def test_payload_digest_binds_all_fields():
    base = crypto.payload_digest("OP", "w", 1, ["a", "b"], 2, 3, 4)
    assert base == crypto.payload_digest("OP", "w", 1, ["a", "b"], 2, 3, 4)
    assert base != crypto.payload_digest("OP2", "w", 1, ["a", "b"], 2, 3, 4)
    assert base != crypto.payload_digest("OP", "w2", 1, ["a", "b"], 2, 3, 4)
    assert base != crypto.payload_digest("OP", "w", 2, ["a", "b"], 2, 3, 4)
    assert base != crypto.payload_digest("OP", "w", 1, ["b", "a"], 2, 3, 4)
    assert base != crypto.payload_digest("OP", "w", 1, ["a", "b"], 3, 3, 4)
    assert base != crypto.payload_digest("OP", "w", 1, ["a", "b"], 2, 4, 4)
    assert base != crypto.payload_digest("OP", "w", 1, ["a", "b"], 2, 3, 5)
