from pathlib import Path

from greynoc_nhi.cli import build_parser
from greynoc_nhi.engine import Engine


def test_repo_scan_detects_pam_persistence_script(tmp_path: Path) -> None:
    script = tmp_path / "install.sh"
    script.write_text(
        "\n".join(
            [
                "cp pam_backdoor.so /lib/x86_64-linux-gnu/security/pam_backdoor.so",
                "echo 'auth required /tmp/pam_backdoor.so' >> /etc/pam.d/sshd",
                "HISTFILE=/dev/null",
                "echo $SSH_CONNECTION",
            ]
        ),
        encoding="utf-8",
    )
    result = Engine(tmp_path / "db.sqlite3", cache_enabled=False).run_scan(tmp_path, persist=False, enrich_owners=False)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "nhi_linux_pam_auth_chain_modified" in rule_ids
    assert "nhi_linux_pam_module_outside_trusted_dir" in rule_ids
    assert "nhi_linux_pam_ssh_credential_theft_indicators" in rule_ids
    assert "nhi_linux_pam_antiforensics_indicators" in rule_ids
    assert result.stats["scan_surface"] == "repo"


def test_host_audit_detects_pam_module_risks(tmp_path: Path) -> None:
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    (pam_dir / "sshd").write_text(
        "\n".join(
            [
                "auth required /opt/pam_backdoor.so",
                "auth sufficient pam_missing.so",
            ]
        ),
        encoding="utf-8",
    )
    security_dir = tmp_path / "usr" / "lib" / "security"
    security_dir.mkdir(parents=True)
    (security_dir / "pam_backdoor.so").write_bytes(b"\x7fELF\x00SSH_CONNECTION\x00PAM_AUTHTOK\x00")

    result = Engine(tmp_path / "db.sqlite3", cache_enabled=False).run_host_audit(tmp_path, persist=False)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "nhi_linux_pam_module_outside_trusted_dir" in rule_ids
    assert "nhi_linux_pam_referenced_module_missing" in rule_ids
    assert "nhi_linux_pam_unknown_module" in rule_ids
    assert "nhi_linux_pam_ssh_credential_theft_indicators" in rule_ids
    assert result.stats["scan_surface"] == "host"
    assert result.stats["host_audit"]["linux_auth"] is True


def test_host_audit_cli_flags_parse() -> None:
    args = build_parser().parse_args(["--host-audit", "--linux-auth-audit", "--host-root", "/", "--no-elf-strings"])
    assert args.host_audit is True
    assert args.linux_auth_audit is True
    assert args.host_root == "/"
    assert args.no_elf_strings is True
