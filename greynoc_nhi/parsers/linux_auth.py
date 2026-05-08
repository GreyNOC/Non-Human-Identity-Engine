"""Linux PAM and SSH persistence parser for repo-side artifacts."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal

__version__ = 1

PAM_CONFIG_NAMES = {"sshd", "common-auth", "system-auth", "password-auth", "login", "sudo", "su"}
DEPLOYMENT_SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".tf", ".conf", ".cfg", ".ini", ".md", ".txt"}
TRUSTED_MODULE_DIR_RE = re.compile(r"^/(?:lib(?:64)?|lib/[^/]+|usr/lib[^/]*|usr/local/lib[^/]*)/security/", re.I)
PAM_LINE_RE = re.compile(r"^\s*(auth|account|password|session)\s+(\S+)\s+(\S+)", re.I)
PAM_PATH_RE = re.compile(r"/etc/pam\.d/(?:sshd|common-auth|system-auth|password-auth|login|sudo|su)\b", re.I)
SECURITY_MODULE_PATH_RE = re.compile(r"(?P<path>/(?:lib(?:64)?|lib/[^/\s]+|usr/lib[^\s/]*|usr/local/lib[^\s/]*)/security/[A-Za-z0-9_.+-]+\.so)", re.I)
ABSOLUTE_SO_RE = re.compile(r"(?P<path>/(?:[^ \t'\";]+/)+[A-Za-z0-9_.+-]+\.so)")
PAM_MODIFY_RE = re.compile(
    r"(?:(?:sed|perl)\s+-i\b.*?/etc/pam\.d/|echo\b.*?(?:>>|tee\s+-a)\s*/etc/pam\.d/|(?:cp|install|mv)\b.*?\.so\b.*?/security/)",
    re.I,
)
PAM_SENSITIVE_MODULES = {"pam_exec.so", "pam_python.so"}
KNOWN_PAM_MODULES = {
    "pam_access.so",
    "pam_cap.so",
    "pam_debug.so",
    "pam_deny.so",
    "pam_echo.so",
    "pam_env.so",
    "pam_exec.so",
    "pam_faildelay.so",
    "pam_faillock.so",
    "pam_filter.so",
    "pam_ftp.so",
    "pam_group.so",
    "pam_issue.so",
    "pam_keyinit.so",
    "pam_lastlog.so",
    "pam_limits.so",
    "pam_listfile.so",
    "pam_localuser.so",
    "pam_loginuid.so",
    "pam_mail.so",
    "pam_mkhomedir.so",
    "pam_motd.so",
    "pam_namespace.so",
    "pam_nologin.so",
    "pam_permit.so",
    "pam_pwhistory.so",
    "pam_rhosts.so",
    "pam_rootok.so",
    "pam_securetty.so",
    "pam_selinux.so",
    "pam_sepermit.so",
    "pam_shells.so",
    "pam_sss.so",
    "pam_succeed_if.so",
    "pam_systemd.so",
    "pam_tally2.so",
    "pam_time.so",
    "pam_timestamp.so",
    "pam_umask.so",
    "pam_unix.so",
    "pam_userdb.so",
    "pam_warn.so",
    "pam_wheel.so",
    "pam_xauth.so",
}
SSH_CRED_THEFT_RE = re.compile(r"\b(SSH_CONNECTION|SSH_CLIENT|SSH_TTY|PAM_AUTHTOK|pam_get_authtok|getpwnam|getspnam)\b", re.I)
ANTIFORENSICS_RE = re.compile(r"\b(HISTFILE\s*=\s*/dev/null|unset\s+HISTFILE|lastlog|utmp|wtmp|auditctl\s+-D)\b", re.I)


def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    return (
        "/etc/pam.d/" in normalized
        or "/pam.d/" in normalized
        or name in PAM_CONFIG_NAMES
        or name == "sshd_config"
        or name == "dockerfile"
        or path.suffix.lower() in DEPLOYMENT_SUFFIXES
    )


def _trusted_module_path(path: str) -> bool:
    return bool(TRUSTED_MODULE_DIR_RE.search(path.replace("\\", "/")))


def _module_name(module: str) -> str:
    return module.replace("\\", "/").rsplit("/", 1)[-1]


def _line_for_path(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def _is_pam_context(path: Path, text: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    lower = text.lower()
    return "/etc/pam.d/" in normalized or "/pam.d/" in normalized or "pam_" in lower or "/etc/pam.d/" in lower or "usepam" in lower


def _signal(
    *,
    rule_id: str,
    path: Path,
    line: int | None,
    name: str,
    evidence: str,
    admin_access: bool = True,
    confidence: str = "high",
    tags: list[str] | None = None,
) -> Signal:
    return make_signal(
        rule_id=rule_id,
        file_path=path,
        line_number=line,
        name=name,
        identity_type="linux_auth_module",
        source="linux PAM/SSH config",
        evidence=evidence,
        permissions=["host_authentication"],
        data_classes=["ssh_credentials"],
        admin_access=admin_access,
        production_access=True,
        approval_required=False,
        tags=["linux_auth", "pam", *(tags or [])],
        confidence=confidence,
    )


def _parse_pam_line(path: Path, text: str, line: str, number: int) -> list[Signal]:
    signals: list[Signal] = []
    match = PAM_LINE_RE.match(line)
    if not match:
        return signals
    control, flag, module = match.groups()
    module_name = _module_name(module)
    if module.endswith(".so") and module.startswith("/"):
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_absolute_module_path",
                path=path,
                line=number,
                name="PAM absolute module path",
                evidence=line.strip(),
                tags=["absolute_module_path"],
            )
        )
        if not _trusted_module_path(module):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_module_outside_trusted_dir",
                    path=path,
                    line=number,
                    name="PAM module outside trusted directory",
                    evidence=line.strip(),
                    tags=["persistence_path"],
                )
            )
    if module_name in PAM_SENSITIVE_MODULES:
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_persistence_path",
                path=path,
                line=number,
                name=f"PAM {module_name} persistence path",
                evidence=line.strip(),
                tags=["persistence_path", module_name],
            )
        )
    if module_name.endswith(".so") and module_name.startswith("pam_") and module_name not in KNOWN_PAM_MODULES:
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_unknown_module",
                path=path,
                line=number,
                name="Unknown PAM module reference",
                evidence=line.strip(),
                confidence="medium",
                tags=["unknown_module"],
            )
        )
    if control.lower() == "auth" and (module_name in PAM_SENSITIVE_MODULES or module.startswith("/")):
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_auth_chain_modified",
                path=path,
                line=number,
                name="PAM auth chain modified",
                evidence=f"{control} {flag} {module}",
                tags=["auth_chain"],
            )
        )
    return signals


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    if not _is_pam_context(path, text):
        return signals

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        signals.extend(_parse_pam_line(path, text, stripped, number))
        if "usepam" in stripped.lower():
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_auth_chain_modified",
                    path=path,
                    line=number,
                    name="SSH UsePAM setting changed",
                    evidence=stripped,
                    confidence="medium",
                    tags=["sshd_config"],
                )
            )
        if SSH_CRED_THEFT_RE.search(stripped):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_ssh_credential_theft_indicators",
                    path=path,
                    line=number,
                    name="SSH/PAM credential-theft indicator",
                    evidence=stripped,
                    tags=["credential_theft"],
                )
            )
        if ANTIFORENSICS_RE.search(stripped):
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_antiforensics_indicators",
                    path=path,
                    line=number,
                    name="PAM/SSH anti-forensics indicator",
                    evidence=stripped,
                    tags=["antiforensics"],
                )
            )

    if PAM_MODIFY_RE.search(text):
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_auth_chain_modified",
                path=path,
                line=_line_for_path(text, "/etc/pam.d/") or _line_for_path(text, "/security/"),
                name="Script modifies PAM authentication chain",
                evidence="Script appears to edit /etc/pam.d or install a PAM module",
                tags=["auth_chain", "deployment_script"],
            )
        )
    for match in SECURITY_MODULE_PATH_RE.finditer(text):
        module_path = match.group("path")
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_persistence_path",
                path=path,
                line=_line_for_path(text, module_path),
                name="PAM module installation path",
                evidence=module_path,
                tags=["persistence_path"],
            )
        )
    for match in ABSOLUTE_SO_RE.finditer(text):
        module_path = match.group("path")
        if ".so" in module_path and "security" not in module_path and "/etc/pam.d/" in text:
            signals.append(
                _signal(
                    rule_id="nhi_linux_pam_module_outside_trusted_dir",
                    path=path,
                    line=_line_for_path(text, module_path),
                    name="PAM absolute module outside trusted security dirs",
                    evidence=module_path,
                    tags=["persistence_path"],
                )
            )
    if PAM_PATH_RE.search(text) and (" >> " in text or "tee -a" in text or "sed -i" in text):
        signals.append(
            _signal(
                rule_id="nhi_linux_pam_auth_chain_modified",
                path=path,
                line=_line_for_path(text, "/etc/pam.d/"),
                name="PAM config append or in-place edit",
                evidence="Command modifies PAM config under /etc/pam.d",
                tags=["auth_chain"],
            )
        )
    return signals
