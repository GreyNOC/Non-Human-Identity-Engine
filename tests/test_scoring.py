from greynoc_nhi.models import NonHumanIdentity
from greynoc_nhi.scoring import finding_severity, score_identity


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


def test_finding_severity_bands_are_stable():
    """The low-confidence damping in rules.make_finding moves scores exactly one
    band (-25), so the band edges themselves must stay fixed."""
    assert finding_severity(85) == "critical"
    assert finding_severity(84) == "high"
    assert finding_severity(65) == "high"
    assert finding_severity(64) == "medium"
    assert finding_severity(40) == "medium"
    assert finding_severity(39) == "low"
    assert finding_severity(20) == "low"
