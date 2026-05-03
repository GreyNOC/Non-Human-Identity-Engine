from greynoc_nhi.masking import fingerprint_secret, mask_secret


def test_mask_secret_never_returns_full_value():
    secret = "sk_live_GNOC_FAKE_SECRET_DO_NOT_USE_123456"
    masked = mask_secret(secret)
    assert masked != secret
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in masked
    assert masked.startswith("sk_l")


def test_secret_fingerprint_is_stable():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE"
    assert fingerprint_secret(secret) == fingerprint_secret(secret)
