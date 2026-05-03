from greynoc_nhi.models import NonHumanIdentity
from greynoc_nhi.scoring import score_identity


def test_scoring_critical_for_plaintext_admin_secret():
    identity = NonHumanIdentity(
        id="1",
        name="admin secret",
        identity_type="API key",
        source="test",
        has_secret=True,
        admin_access=True,
        production_access=True,
        external_access=True,
        data_access_level="customer",
        rotation_status="missing",
        logging_enabled=False,
    )
    assert score_identity(identity) >= 80
