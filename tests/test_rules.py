from greynoc_nhi.engine import normalize_signal
from greynoc_nhi.rules import run_rules


def test_rules_generate_secret_leakage_finding():
    identity = normalize_signal({"rule_id": "nhi_secret_leakage", "file_path": "x", "line_number": 1, "name": "API_KEY", "identity_type": "API key", "source": "test", "evidence": ["API_KEY=ABCD...WXYZ"], "secret_value": "GNOC_FAKE_SECRET_DO_NOT_USE_123456"})
    findings = run_rules([identity])
    assert any(f.rule_id == "nhi_secret_leakage" for f in findings)
