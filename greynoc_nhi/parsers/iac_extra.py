"""IaC parser covering Pulumi, AWS CDK, and Azure Bicep.

These three ecosystems all sit alongside Terraform but are not parsed by the
existing terraform parser. Each carries a different shape of risk:

* **Pulumi** — `Pulumi.yaml` / `Pulumi.<stack>.yaml` `config:` sections often
  contain literal credentials when developers skip `pulumi config set --secret`.
* **AWS CDK** — `cdk.context.json` is auto-generated and sometimes contains
  account IDs and credentials; `cdk.json` may carry context overrides too.
* **Azure Bicep** — `param` declarations whose default value is a literal
  secret, or `param` whose name implies secret but is missing `@secure()`.
"""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for_key_value, parse_json_safely

PULUMI_FILE_RE = re.compile(r"^pulumi(?:\.[\w.-]+)?\.ya?ml$", re.IGNORECASE)
CDK_FILES = {"cdk.json", "cdk.context.json"}
BICEP_SUFFIXES = {".bicep"}

SECRET_HINT_RE = re.compile(
    r"(secret|password|passwd|api[_-]?key|token|client[_-]?secret|private[_-]?key|connection[_-]?string|credential)",
    re.IGNORECASE,
)
PULUMI_KV_RE = re.compile(
    r"^(\s*)([A-Za-z][\w.:-]*)\s*:\s*(?:['\"]?)([^#\n]*?)(?:['\"]?)\s*(?:#.*)?$"
)
BICEP_PARAM_RE = re.compile(
    r"^\s*(?:@secure\(\)\s*)?param\s+([A-Za-z_][\w]*)\s+(\w+)(?:\s*=\s*(.+))?$"
)


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    if PULUMI_FILE_RE.match(name):
        return True
    if name in CDK_FILES:
        return True
    if path.suffix.lower() in BICEP_SUFFIXES:
        return True
    return False


def _parse_pulumi(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    in_config = False
    config_indent = 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        bare = line.split("#", 1)[0]
        leading = len(bare) - len(bare.lstrip(" "))
        if re.match(r"^\s*config\s*:\s*(#|$)", line):
            in_config = True
            config_indent = leading
            continue
        if in_config and stripped and leading <= config_indent and not stripped.startswith("#"):
            in_config = False
        if not in_config:
            continue
        match = PULUMI_KV_RE.match(line)
        if not match:
            continue
        key = match.group(2)
        value = match.group(3).strip()
        if not value or value in {"~", "null", "{}", "[]"}:
            continue
        if value.startswith("$") or value.startswith("{{"):
            continue
        if not SECRET_HINT_RE.search(key):
            continue
        if not looks_like_secret(value):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_pulumi_config_plaintext_secret",
                file_path=path,
                line_number=number,
                name=key,
                identity_type="cloud_workload_identity",
                source="pulumi",
                evidence=line.strip(),
                secret_value=value,
                provider="pulumi",
                tags=["pulumi", "iac", "plaintext_secret"],
            )
        )
    return signals


def _parse_cdk(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    if data is None:
        return []
    signals: list[Signal] = []
    for key, value in flatten_json(data):
        if not isinstance(value, str) or not value:
            continue
        last = key.split(".")[-1].split("[")[0].lower()
        if not SECRET_HINT_RE.search(last):
            continue
        if not looks_like_secret(value):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_aws_cdk_context_secret",
                file_path=path,
                line_number=line_number_for_key_value(text, key, value),
                name=f"CDK context: {last}",
                identity_type="cloud_workload_identity",
                source="aws cdk",
                evidence=f"{key}={value}",
                secret_value=value,
                provider="aws",
                tags=["aws_cdk", "iac", "plaintext_secret"],
            )
        )
    return signals


def _parse_bicep(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        match = BICEP_PARAM_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        ptype = match.group(2)
        default_val = (match.group(3) or "").strip()
        is_secret_name = bool(SECRET_HINT_RE.search(name))
        is_string_type = ptype.lower() in {"string", "securestring"}
        has_secure_decorator = False
        for prior in lines[max(0, number - 3): number - 1]:
            if "@secure(" in prior:
                has_secure_decorator = True
                break
        if is_secret_name and is_string_type and not has_secure_decorator:
            signals.append(
                make_signal(
                    rule_id="nhi_bicep_param_missing_secure_decorator",
                    file_path=path,
                    line_number=number,
                    name=name,
                    identity_type="cloud_workload_identity",
                    source="bicep",
                    evidence=line.strip(),
                    provider="azure",
                    tags=["bicep", "iac", "missing_secure"],
                    confidence="high",
                )
            )
        if default_val and default_val.startswith("'") and default_val.endswith("'"):
            literal = default_val.strip("'")
            if is_secret_name and looks_like_secret(literal):
                signals.append(
                    make_signal(
                        rule_id="nhi_bicep_param_default_plaintext_secret",
                        file_path=path,
                        line_number=number,
                        name=name,
                        identity_type="cloud_workload_identity",
                        source="bicep",
                        evidence=line.strip(),
                        secret_value=literal,
                        provider="azure",
                        tags=["bicep", "iac", "plaintext_secret"],
                    )
                )
    return signals


def parse(path: Path, text: str) -> list[Signal]:
    name = path.name.lower()
    if PULUMI_FILE_RE.match(name):
        return _parse_pulumi(path, text)
    if name in CDK_FILES:
        return _parse_cdk(path, text)
    if path.suffix.lower() in BICEP_SUFFIXES:
        return _parse_bicep(path, text)
    return []
