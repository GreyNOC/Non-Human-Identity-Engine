import json
from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.baseline import apply_baseline, has_new_findings_at_or_above, write_baseline
from greynoc_nhi.confidence import is_placeholder_value
from greynoc_nhi.engine import Engine
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers import cloud_credentials, generic_config, oauth_configs, webhooks
from greynoc_nhi.reports import generate_html_report, generate_json_report, generate_markdown_report
from greynoc_nhi.sarif import generate_sarif_report
from greynoc_nhi.storage import Storage


def test_placeholder_suppression_and_gnoc_fixture_marker():
    assert is_placeholder_value("replace-me")
    assert not looks_like_secret("replace-me")
    assert not looks_like_secret("${API_KEY}")
    assert not looks_like_secret("${{ secrets.PROD_TOKEN }}")
    assert looks_like_secret("GNOC_FAKE_SECRET_DO_NOT_USE_123456")


def test_generic_config_line_number_and_suppression():
    text = '{\n  "api_key": "replace-me",\n  "client_secret": "GNOC_FAKE_SECRET_DO_NOT_USE_123456"\n}\n'
    signals = generic_config.parse(Path("config.json"), text)
    assert len(signals) == 1
    assert signals[0]["line_number"] == 3
    assert signals[0]["confidence"] == "medium"


def test_cloud_oauth_and_webhook_line_numbers():
    cloud = cloud_credentials.parse(Path("creds.txt"), "one\nAKIAABCDEFGHIJKLMNOP\n")
    oauth = oauth_configs.parse(Path("oauth.json"), '{\n  "client_secret": "GNOC_FAKE_SECRET_DO_NOT_USE_123456"\n}\n')
    webhook = webhooks.parse(Path("hook.txt"), "x\nhttps://hooks.slack.com/services/T000/B000/GNOC_FAKE_SECRET_DO_NOT_USE\n")
    assert cloud[0]["line_number"] == 2
    assert oauth[0]["line_number"] == 2
    assert webhook[0]["line_number"] == 2


def test_sarif_generation_has_required_keys():
    temp_dir = Path(mkdtemp(prefix="greynoc_sarif_"))
    project = temp_dir / "project"
    project.mkdir()
    (project / ".env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456\n", encoding="utf-8")
    result = Engine(temp_dir / "db.sqlite3").run_scan(project)
    sarif_path = generate_sarif_report(result, temp_dir / "out.sarif")
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert "tool" in data["runs"][0]
    assert "results" in data["runs"][0]


def test_greynocignore_skips_matching_files():
    temp_dir = Path(mkdtemp(prefix="greynoc_ignore_"))
    (temp_dir / ".greynocignore").write_text("ignored.env\nsamples/*\n", encoding="utf-8")
    (temp_dir / "ignored.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456\n", encoding="utf-8")
    samples = temp_dir / "samples"
    samples.mkdir()
    (samples / "also.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_999999\n", encoding="utf-8")
    result = Engine(temp_dir / "db.sqlite3").run_scan(temp_dir)
    assert result.stats["scanned_files"] == 0
    assert not result.findings


def test_baseline_write_apply_and_fail_on_new():
    temp_dir = Path(mkdtemp(prefix="greynoc_baseline_"))
    project = temp_dir / "project"
    project.mkdir()
    (project / ".env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456\n", encoding="utf-8")
    result = Engine(temp_dir / "db.sqlite3").run_scan(project)
    baseline_path = write_baseline(result, temp_dir / "baseline.json")
    apply_baseline(result, baseline_path)
    assert result.findings
    assert all(f.baseline_status == "known" for f in result.findings)
    assert not has_new_findings_at_or_above(result, "critical")


def test_custom_json_rule_pack_masks_evidence():
    temp_dir = Path(mkdtemp(prefix="greynoc_custom_"))
    project = temp_dir / "project"
    project.mkdir()
    raw_secret = "GNOC_ADMIN_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    (project / "settings.txt").write_text(f"admin={raw_secret}\n", encoding="utf-8")
    rule_pack = temp_dir / "rules.json"
    rule_pack.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "company_internal_admin_token",
                        "title": "Internal admin token detected",
                        "severity": "critical",
                        "pattern": "GNOC_ADMIN_[A-Za-z0-9]{24,}",
                        "identity_type": "internal admin token",
                        "provider": "greynoc",
                        "remediation": "Rotate the token and move it to a managed secret store.",
                        "confidence": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = Engine(temp_dir / "db.sqlite3", rule_pack_path=rule_pack).run_scan(project)
    assert any(f.rule_id == "company_internal_admin_token" for f in result.findings)
    assert raw_secret not in json.dumps(result.to_dict())


def test_raw_secret_never_leaks_to_reports_or_storage():
    temp_dir = Path(mkdtemp(prefix="greynoc_no_leak_"))
    project = temp_dir / "project"
    project.mkdir()
    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_SUPER_RAW_123456"
    (project / ".env").write_text(f"API_KEY={raw_secret}\n", encoding="utf-8")
    db_path = temp_dir / "db.sqlite3"
    result = Engine(db_path).run_scan(project)
    outputs = [
        generate_html_report(result, temp_dir),
        generate_json_report(result, temp_dir),
        generate_markdown_report(result, temp_dir),
        generate_sarif_report(result, temp_dir / "scan.sarif"),
        write_baseline(result, temp_dir / "baseline.json"),
    ]
    for output in outputs:
        assert raw_secret not in output.read_text(encoding="utf-8")
    loaded = Storage(db_path).get_scan(result.scan_id)
    assert loaded is not None
    assert raw_secret not in json.dumps(loaded.to_dict())
    for suffix in ("", "-wal", "-shm", "-journal"):
        artifact = Path(f"{db_path}{suffix}")
        if artifact.exists():
            assert raw_secret.encode() not in artifact.read_bytes()
