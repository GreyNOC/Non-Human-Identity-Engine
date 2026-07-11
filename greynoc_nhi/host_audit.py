"""Read-only host audit helpers for Linux PAM and SSH authentication paths."""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from greynoc_nhi.masking import redact_inline_secret
from greynoc_nhi.parsers import linux_auth
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.scanner import dedupe_signals
from greynoc_nhi.utils import read_text_safely

MAX_ELF_STRING_BYTES = 256 * 1024
STRING_RE = re.compile(rb"[ -~]{5,}")
MODULE_REF_RE = re.compile(r"^\s*(auth|account|password|session)\s+\S+\s+(?P<module>\S+)", re.I)
# Legacy /etc/pam.conf format carries a leading service field before the facility keyword.
PAM_CONF_MODULE_REF_RE = re.compile(r"^\s*\S+\s+(auth|account|password|session)\s+\S+\s+(?P<module>\S+)", re.I)
STRING_CRED_RE = re.compile(r"\b(SSH_CONNECTION|SSH_CLIENT|SSH_TTY|PAM_AUTHTOK|pam_get_authtok|getpwnam|getspnam|password=|curl\s+https?://|wget\s+https?://)\b", re.I)
STRING_ANTIFORENSICS_RE = re.compile(r"\b(HISTFILE=/dev/null|unset HISTFILE|lastlog|utmp|wtmp|auditctl -D)\b", re.I)


def _world_writable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _host_path(root: Path, absolute_path: str) -> Path:
    relative = absolute_path.lstrip("/").replace("/", "\\") if "\\" in str(root) else absolute_path.lstrip("/")
    return root / relative


def _display_path(root: Path, path: Path) -> str:
    try:
        return "/" + str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def _security_dirs(root: Path) -> list[Path]:
    dirs: list[Path] = []
    patterns = [
        "lib/*/security",
        "lib64/security",
        "usr/lib/security",
        "usr/lib*/security",
        "usr/local/lib/security",
        "usr/local/lib*/security",
    ]
    for pattern in patterns:
        dirs.extend(path for path in root.glob(pattern) if path.is_dir())
    return sorted(set(dirs))


def _pam_configs(root: Path) -> list[Path]:
    pam_dir = root / "etc" / "pam.d"
    if not pam_dir.is_dir():
        return []
    try:
        return sorted(path for path in pam_dir.iterdir() if path.is_file() and not path.is_symlink())
    except OSError:
        return []


def _bounded_strings(path: Path) -> list[str]:
    try:
        data = path.read_bytes()[:MAX_ELF_STRING_BYTES]
    except OSError:
        return []
    return [match.group(0).decode("utf-8", errors="replace") for match in STRING_RE.finditer(data)]


def _signal(
    *,
    rule_id: str,
    path: Path,
    root: Path,
    line: int | None,
    name: str,
    evidence: str,
    tags: list[str] | None = None,
    confidence: str = "high",
) -> Signal:
    return make_signal(
        rule_id=rule_id,
        file_path=_display_path(root, path),
        line_number=line,
        name=name,
        identity_type="linux_auth_module",
        source="host linux auth audit",
        evidence=redact_inline_secret(evidence),
        permissions=["host_authentication"],
        data_classes=["ssh_credentials"],
        admin_access=True,
        production_access=True,
        approval_required=False,
        tags=["host_audit", "linux_auth", "pam", *(tags or [])],
        confidence=confidence,
    )


def _module_candidates(root: Path, module: str, security_dirs: list[Path]) -> list[Path]:
    if module.startswith("/"):
        return [_host_path(root, module)]
    if "/" in module:
        return [_host_path(root, "/" + module.lstrip("/"))]
    return [directory / module for directory in security_dirs]


def _module_exists(root: Path, module: str, security_dirs: list[Path]) -> bool:
    return any(candidate.exists() for candidate in _module_candidates(root, module, security_dirs))


def _line_number(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def _sshd_config_dropins(root: Path) -> list[Path]:
    dropin_dir = root / "etc" / "ssh" / "sshd_config.d"
    if not dropin_dir.is_dir():
        return []
    try:
        return sorted(path for path in dropin_dir.glob("*.conf") if path.is_file())
    except OSError:
        return []


def _pam_module_ref_signals(root: Path, config: Path, text: str, security_dirs: list[Path]) -> list[Signal]:
    signals: list[Signal] = []
    module_ref_re = PAM_CONF_MODULE_REF_RE if config.name.lower() == "pam.conf" else MODULE_REF_RE
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = module_ref_re.match(line)
        if not match:
            continue
        module = match.group("module")
        module_name = module.replace("\\", "/").rsplit("/", 1)[-1]
        if module.endswith(".so") and module.startswith("/") and not linux_auth._trusted_module_path(module):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_module_outside_trusted_dir",
                    path=config,
                    root=root,
                    line=number,
                    name="PAM module outside trusted directory",
                    evidence=line.strip(),
                    tags=["persistence_path"],
                )
            )
        if module.endswith(".so") and not _module_exists(root, module, security_dirs):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_referenced_module_missing",
                    path=config,
                    root=root,
                    line=number,
                    name="PAM referenced module missing",
                    evidence=line.strip(),
                    tags=["missing_module"],
                    confidence="medium",
                )
            )
        if module_name.endswith(".so") and module_name.startswith("pam_") and module_name not in linux_auth.KNOWN_PAM_MODULES:
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_unknown_module",
                    path=config,
                    root=root,
                    line=number,
                    name="Unknown PAM module reference",
                    evidence=line.strip(),
                    tags=["unknown_module"],
                    confidence="medium",
                )
            )
    return signals


def audit_linux_auth(host_root: str | Path = "/", *, no_elf_strings: bool = False) -> dict[str, Any]:
    """Inspect Linux auth files without executing modules or commands."""
    root = Path(host_root).resolve()
    signals: list[Signal] = []
    errors: list[dict[str, str]] = []
    scanned_files = 0
    skipped_files = 0
    security_dirs = _security_dirs(root)
    sshd_dropins = _sshd_config_dropins(root)

    for config in [
        *_pam_configs(root),
        root / "etc" / "pam.conf",
        root / "etc" / "ssh" / "sshd_config",
        *sshd_dropins,
    ]:
        if not config.exists() or not config.is_file() or config.is_symlink():
            continue
        text = read_text_safely(config)
        if text is None:
            skipped_files += 1
            errors.append({"file": _display_path(root, config), "parser": "host_audit", "error": "unreadable auth config"})
            continue
        scanned_files += 1
        if _world_writable(config):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_config_world_writable",
                    path=config,
                    root=root,
                    line=None,
                    name="PAM/SSH config is world-writable",
                    evidence=f"{_display_path(root, config)} is writable by other users",
                    tags=["world_writable"],
                )
            )
        for signal in linux_auth.parse(Path(_display_path(root, config)), text):
            signal["source"] = "host linux auth audit"
            signal["tags"] = list(signal.get("tags", [])) + ["host_audit"]
            signals.append(signal)
        signals.extend(_pam_module_ref_signals(root, config, text, security_dirs))

    for directory in security_dirs:
        try:
            modules = sorted(path for path in directory.glob("*.so") if path.is_file() and not path.is_symlink())
        except OSError:
            continue
        for module in modules:
            scanned_files += 1
            display = _display_path(root, module)
            module_name = module.name
            if _world_writable(module):
                signals.append(
                    _signal(
                        rule_id="nhi_linux_pam_module_world_writable",
                        path=module,
                        root=root,
                        line=None,
                        name="PAM module is world-writable",
                        evidence=f"{display} is writable by other users",
                        tags=["world_writable"],
                    )
                )
            if module_name.startswith("pam_") and module_name not in linux_auth.KNOWN_PAM_MODULES:
                signals.append(
                    _signal(
                        rule_id="nhi_linux_pam_unknown_module",
                        path=module,
                        root=root,
                        line=None,
                        name="Unknown PAM module on host",
                        evidence=f"{display} is not in the built-in common PAM module list",
                        tags=["unknown_module"],
                        confidence="medium",
                    )
                )
            if no_elf_strings:
                continue
            strings = "\n".join(_bounded_strings(module))
            if STRING_CRED_RE.search(strings):
                signals.append(
                    _signal(
                        rule_id="nhi_linux_pam_ssh_credential_theft_indicators",
                        path=module,
                        root=root,
                        line=None,
                        name="PAM module contains SSH/PAM credential strings",
                        evidence=f"{display} contains bounded strings referencing SSH/PAM credential material",
                        tags=["credential_theft", "elf_strings"],
                    )
                )
            if STRING_ANTIFORENSICS_RE.search(strings):
                signals.append(
                    _signal(
                        rule_id="nhi_linux_pam_antiforensics_indicators",
                        path=module,
                        root=root,
                        line=None,
                        name="PAM module contains anti-forensics strings",
                        evidence=f"{display} contains bounded strings referencing shell history or login-record tampering",
                        tags=["antiforensics", "elf_strings"],
                    )
                )

    return {
        "project_path": str(root),
        "signals": dedupe_signals(signals),
        "errors": errors,
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "ignore_patterns": [],
        "custom_rules": [],
        "cache_hits": 0,
        "cache_misses": 0,
        "scan_surface": "host",
        "host_audit": {
            "linux_auth": True,
            "no_elf_strings": no_elf_strings,
            "security_dirs": [_display_path(root, path) for path in security_dirs],
            "sshd_config_dropins": [_display_path(root, path) for path in sshd_dropins],
        },
    }
