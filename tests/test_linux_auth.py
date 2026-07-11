from pathlib import Path

from greynoc_nhi.cli import build_parser
from greynoc_nhi.engine import Engine
from greynoc_nhi.host_audit import audit_linux_auth
from greynoc_nhi.parsers import linux_auth


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


def test_stock_sshd_config_usepam_yes_not_flagged() -> None:
    signals = linux_auth.parse(Path("/etc/ssh/sshd_config"), "UsePAM yes\nPermitRootLogin no\n")
    assert signals == []


def test_sshd_config_usepam_no_flagged() -> None:
    signals = linux_auth.parse(Path("/etc/ssh/sshd_config"), "UsePAM no\n")
    assert len(signals) == 1
    assert signals[0]["rule_id"] == "nhi_linux_pam_auth_chain_modified"
    assert signals[0]["name"] == "SSH UsePAM disabled"
    assert signals[0]["confidence"] == "medium"
    assert signals[0]["line_number"] == 1


def test_deployment_script_usepam_toggle_low_confidence() -> None:
    signals = linux_auth.parse(Path("install.sh"), 'echo "UsePAM yes" >> /etc/ssh/sshd_config\n')
    names = [signal["name"] for signal in signals]
    assert "SSH UsePAM setting changed" in names
    toggled = next(signal for signal in signals if signal["name"] == "SSH UsePAM setting changed")
    assert toggled["confidence"] == "low"


def test_stock_distro_pam_modules_not_flagged_unknown() -> None:
    text = "\n".join(
        [
            "password requisite pam_pwquality.so retry=3",
            "auth sufficient pam_usertype.so issystem",
            "auth optional pam_gnome_keyring.so",
            "session optional pam_systemd_home.so",
            "session optional pam_oddjob_mkhomedir.so",
            "auth sufficient pam_fprintd.so",
        ]
    )
    signals = linux_auth.parse(Path("etc/pam.d/system-auth"), text)
    assert not any(signal["rule_id"] == "nhi_linux_pam_unknown_module" for signal in signals)


def test_unrecognized_pam_module_still_flagged_unknown() -> None:
    signals = linux_auth.parse(Path("etc/pam.d/sshd"), "auth required pam_evil.so\n")
    assert any(signal["rule_id"] == "nhi_linux_pam_unknown_module" for signal in signals)


def test_security_substring_directory_is_not_trusted() -> None:
    text = "\n".join(
        [
            "cp pam_evil.so /opt/security-tools/pam_evil.so",
            "echo 'auth required pam_unix.so' >> /etc/pam.d/sshd",
        ]
    )
    signals = linux_auth.parse(Path("deploy.sh"), text)
    outside = [signal for signal in signals if signal["rule_id"] == "nhi_linux_pam_module_outside_trusted_dir"]
    assert outside, "module under a fake 'security' directory must be flagged"
    assert any("/opt/security-tools/pam_evil.so" in signal["evidence"][0] for signal in outside)


def test_multiarch_usr_lib_security_dir_is_trusted() -> None:
    text = "\n".join(
        [
            "cp pam_custom.so /usr/lib/x86_64-linux-gnu/security/pam_custom.so",
            "echo 'auth required pam_unix.so' >> /etc/pam.d/sshd",
        ]
    )
    signals = linux_auth.parse(Path("setup.sh"), text)
    outside = [signal for signal in signals if signal["rule_id"] == "nhi_linux_pam_module_outside_trusted_dir"]
    assert not outside, "Debian multiarch security dir must count as trusted"


def test_host_audit_scans_sshd_dropins_and_pam_conf(tmp_path: Path) -> None:
    dropin_dir = tmp_path / "etc" / "ssh" / "sshd_config.d"
    dropin_dir.mkdir(parents=True)
    (dropin_dir / "99-override.conf").write_text("UsePAM no\n", encoding="utf-8")
    (tmp_path / "etc" / "pam.conf").write_text("login auth required /opt/pam_evil.so\n", encoding="utf-8")

    raw = audit_linux_auth(tmp_path, no_elf_strings=True)
    rule_ids = {signal["rule_id"] for signal in raw["signals"]}
    assert "nhi_linux_pam_auth_chain_modified" in rule_ids
    assert "nhi_linux_pam_module_outside_trusted_dir" in rule_ids
    dropins = raw["host_audit"]["sshd_config_dropins"]
    assert dropins and dropins[0].endswith("99-override.conf")
