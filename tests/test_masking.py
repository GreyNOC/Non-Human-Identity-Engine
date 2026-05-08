import hashlib

from greynoc_nhi.masking import fingerprint_secret, mask_secret


def test_mask_secret_never_returns_full_value():
    secret = "sk_live_GNOC_FAKE_SECRET_DO_NOT_USE_123456"
    masked = mask_secret(secret)
    assert masked != secret
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in masked
    assert "sk_live" not in masked
    assert masked.startswith("[REDACTED:")
    assert "len=" in masked
    assert "fp=" in masked


def test_secret_fingerprint_is_keyed_by_default():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE"
    assert fingerprint_secret(secret, key=b"test") == fingerprint_secret(secret, key=b"test")
    assert fingerprint_secret(secret, key=b"test") != hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert fingerprint_secret(secret, key=b"one") != fingerprint_secret(secret, key=b"two")
