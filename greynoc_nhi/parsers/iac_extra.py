"""IaC/CI parser covering Pulumi, AWS CDK, Azure Bicep, and non-GitHub CI.

These ecosystems all sit alongside Terraform but are not parsed by the
existing terraform parser. Each carries a different shape of risk:

* **Pulumi** — `Pulumi.yaml` / `Pulumi.<stack>.yaml` `config:` sections often
  contain literal credentials when developers skip `pulumi config set --secret`.
* **AWS CDK** — `cdk.context.json` is auto-generated and sometimes contains
  account IDs and credentials; `cdk.json` may carry context overrides too.
* **Azure Bicep** — `param` declarations whose default value is a literal
  secret, or `param` whose name implies secret but is missing `@secure()`.
* **Jenkins / CircleCI / Azure Pipelines / Bitbucket** — CI configs with
  their own syntax (environment{} creds, orbs, System.AccessToken, pipes)
  that GitHub-Actions-specific rules cannot match.
"""

from __future__ import annotations

__version__ = 2

import bisect
import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely

PULUMI_FILE_RE = re.compile(r"^pulumi(?:\.[\w.-]+)?\.ya?ml$", re.IGNORECASE)
CDK_FILES = {"cdk.json", "cdk.context.json"}
BICEP_SUFFIXES = {".bicep"}
JENKINS_FILE_RE = re.compile(r"^jenkinsfile(?:\.[\w.-]+)?$", re.IGNORECASE)
AZURE_PIPELINE_FILES = {"azure-pipelines.yml", "azure-pipelines.yaml"}
BITBUCKET_PIPELINE_FILES = {"bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"}

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
JENKINS_ENV_BLOCK_RE = re.compile(r"^\s*environment\s*\{")
JENKINS_ENV_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]([^'\"]+)['\"]")
JENKINS_CREDENTIALS_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*credentials\(")
CURL_PIPE_SH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k)?sh\b")
CIRCLECI_ORB_RE = re.compile(r"^\s*([\w-]+)\s*:\s*([\w-]+/[\w-]+)@(\S+)\s*$")
CIRCLECI_PINNED_ORB_RE = re.compile(r"\d+\.\d+\.\d+")
CIRCLECI_CONTEXT_RE = re.compile(r"^\s*(-\s*)?context\s*:")
CIRCLECI_MACHINE_TRUE_RE = re.compile(r"^\s*machine\s*:\s*true\b", re.IGNORECASE)
AZURE_PERSIST_CREDENTIALS_RE = re.compile(r"^\s*persistCredentials\s*:\s*['\"]?true", re.IGNORECASE)
BITBUCKET_PIPE_RE = re.compile(r"^\s*-?\s*pipe\s*:\s*(\S+)")


def _line_offsets(text: str) -> list[int]:
    """Precompute line-start offsets for bisect-based line lookups."""
    offsets = [0]
    start = 0
    while True:
        idx = text.find("\n", start)
        if idx == -1:
            return offsets
        offsets.append(idx + 1)
        start = idx + 1


def _line_number_for_key_value(text: str, offsets: list[int], key: str, value: object | None = None) -> int | None:
    """First line containing the key tail or the value, without re-splitting text."""
    key_tail = str(key).split(".")[-1].split("[")[0]
    positions: list[int] = []
    if key_tail:
        pos = text.find(key_tail)
        if pos != -1:
            positions.append(pos)
    value_s = "" if value is None else str(value)
    if value_s and "\n" not in value_s:
        pos = text.find(value_s)
        if pos != -1:
            positions.append(pos)
    if not positions:
        return None
    return bisect.bisect_right(offsets, min(positions))


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    if PULUMI_FILE_RE.match(name):
        return True
    if name in CDK_FILES:
        return True
    if path.suffix.lower() in BICEP_SUFFIXES:
        return True
    if JENKINS_FILE_RE.match(name):
        return True
    if name in AZURE_PIPELINE_FILES or name in BITBUCKET_PIPELINE_FILES:
        return True
    normalized = str(path).replace("\\", "/").lower()
    if ".circleci/" in normalized and name.endswith((".yml", ".yaml")):
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
    offsets = _line_offsets(text)
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
                line_number=_line_number_for_key_value(text, offsets, key, value),
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
        has_secure_decorator = "@secure(" in line
        if not has_secure_decorator:
            for prior in reversed(lines[max(0, number - 6): number - 1]):
                prior_stripped = prior.strip()
                if not prior_stripped or prior_stripped.startswith("param ") or BICEP_PARAM_RE.match(prior):
                    break
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


def _parse_jenkins(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    in_environment = False
    with_credentials_seen = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if JENKINS_ENV_BLOCK_RE.match(line):
            in_environment = True
            continue
        if in_environment and stripped.startswith("}"):
            in_environment = False
            continue
        if in_environment:
            cred_match = JENKINS_CREDENTIALS_RE.match(line)
            if cred_match:
                signals.append(
                    make_signal(
                        rule_id="nhi_jenkins_credentials_binding",
                        file_path=path,
                        line_number=number,
                        name=cred_match.group(1),
                        identity_type="ci_runner",
                        source="jenkins",
                        evidence=stripped,
                        provider="jenkins",
                        tags=["ci_cd", "jenkins", "credential_binding"],
                        confidence="low",
                    )
                )
            else:
                assign_match = JENKINS_ENV_ASSIGN_RE.match(line)
                if assign_match and SECRET_HINT_RE.search(assign_match.group(1)):
                    value = assign_match.group(2).strip()
                    if value and not value.startswith("$") and looks_like_secret(value):
                        signals.append(
                            make_signal(
                                rule_id="nhi_hardcoded_secret",
                                file_path=path,
                                line_number=number,
                                name=assign_match.group(1),
                                identity_type="ci_runner",
                                source="jenkins",
                                evidence=stripped,
                                secret_value=value,
                                provider="jenkins",
                                tags=["ci_cd", "jenkins", "plaintext_secret"],
                            )
                        )
        if not with_credentials_seen and "withCredentials(" in line:
            with_credentials_seen = True
            signals.append(
                make_signal(
                    rule_id="nhi_jenkins_credentials_binding",
                    file_path=path,
                    line_number=number,
                    name="Jenkins withCredentials binding",
                    identity_type="ci_runner",
                    source="jenkins",
                    evidence=stripped,
                    provider="jenkins",
                    tags=["ci_cd", "jenkins", "credential_binding"],
                    confidence="low",
                )
            )
        if CURL_PIPE_SH_RE.search(line):
            signals.append(
                make_signal(
                    rule_id="nhi_ci_remote_script_execution",
                    file_path=path,
                    line_number=number,
                    name="Remote script piped to shell in CI step",
                    identity_type="ci_runner",
                    source="jenkins",
                    evidence=stripped,
                    provider="jenkins",
                    external_access=True,
                    tags=["ci_cd", "jenkins", "remote_script"],
                )
            )
    return signals


def _parse_circleci(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    in_orbs = False
    orbs_indent = 0
    in_environment = False
    environment_indent = 0
    context_seen = False
    remote_docker_seen = False
    for number, line in enumerate(text.splitlines(), 1):
        bare = line.split("#", 1)[0]
        stripped = bare.strip()
        if not stripped:
            continue
        leading = len(bare) - len(bare.lstrip(" "))
        if re.match(r"^\s*orbs\s*:\s*$", bare):
            in_orbs = True
            orbs_indent = leading
            continue
        if in_orbs and leading <= orbs_indent:
            in_orbs = False
        if re.match(r"^\s*environment\s*:\s*$", bare):
            in_environment = True
            environment_indent = leading
            continue
        if in_environment and leading <= environment_indent:
            in_environment = False
        if in_orbs:
            orb_match = CIRCLECI_ORB_RE.match(bare)
            if orb_match and not CIRCLECI_PINNED_ORB_RE.fullmatch(orb_match.group(3)):
                signals.append(
                    make_signal(
                        rule_id="nhi_ci_unpinned_component",
                        file_path=path,
                        line_number=number,
                        name=orb_match.group(2),
                        identity_type="third-party SaaS integration",
                        source="circleci",
                        evidence=stripped,
                        provider="circleci",
                        external_access=True,
                        tags=["ci_cd", "circleci", "third_party", "unpinned"],
                    )
                )
        if in_environment:
            env_match = PULUMI_KV_RE.match(bare)
            if env_match and SECRET_HINT_RE.search(env_match.group(2)):
                value = env_match.group(3).strip()
                if value and not value.startswith("$") and not value.startswith("{{") and looks_like_secret(value):
                    signals.append(
                        make_signal(
                            rule_id="nhi_hardcoded_secret",
                            file_path=path,
                            line_number=number,
                            name=env_match.group(2),
                            identity_type="ci_runner",
                            source="circleci",
                            evidence=stripped,
                            secret_value=value,
                            provider="circleci",
                            tags=["ci_cd", "circleci", "plaintext_secret"],
                        )
                    )
        if not remote_docker_seen and ("setup_remote_docker" in stripped or CIRCLECI_MACHINE_TRUE_RE.match(bare)):
            remote_docker_seen = True
            signals.append(
                make_signal(
                    rule_id="nhi_overprivileged_nhi",
                    file_path=path,
                    line_number=number,
                    name="CircleCI privileged executor",
                    identity_type="ci_runner",
                    source="circleci",
                    evidence=stripped,
                    provider="circleci",
                    admin_access=True,
                    tags=["ci_cd", "circleci", "privileged"],
                    confidence="medium",
                )
            )
        if not context_seen and CIRCLECI_CONTEXT_RE.match(bare):
            context_seen = True
            signals.append(
                make_signal(
                    rule_id="nhi_circleci_context_usage",
                    file_path=path,
                    line_number=number,
                    name="CircleCI context secrets attached",
                    identity_type="ci_runner",
                    source="circleci",
                    evidence=stripped,
                    provider="circleci",
                    tags=["ci_cd", "circleci", "context"],
                    confidence="low",
                )
            )
    return signals


def _parse_azure_pipelines(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    access_token_seen = False
    persist_seen = False
    for number, line in enumerate(text.splitlines(), 1):
        bare = line.split("#", 1)[0]
        stripped = bare.strip()
        if not stripped:
            continue
        if not access_token_seen and "system.accesstoken" in stripped.lower():
            access_token_seen = True
            signals.append(
                make_signal(
                    rule_id="nhi_ci_cd_broad_permissions",
                    file_path=path,
                    line_number=number,
                    name="Azure Pipelines System.AccessToken",
                    identity_type="ci_runner",
                    source="azure pipelines",
                    evidence=stripped,
                    provider="azure devops",
                    permissions=["system.accesstoken"],
                    external_access=True,
                    tags=["ci_cd", "azure_pipelines", "broad_permissions"],
                )
            )
        if not persist_seen and AZURE_PERSIST_CREDENTIALS_RE.match(bare):
            persist_seen = True
            signals.append(
                make_signal(
                    rule_id="nhi_ci_cd_broad_permissions",
                    file_path=path,
                    line_number=number,
                    name="Azure Pipelines persistCredentials",
                    identity_type="ci_runner",
                    source="azure pipelines",
                    evidence=stripped,
                    provider="azure devops",
                    permissions=["persist-credentials"],
                    tags=["ci_cd", "azure_pipelines", "broad_permissions"],
                )
            )
    return signals


def _parse_bitbucket(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        bare = line.split("#", 1)[0]
        stripped = bare.strip()
        pipe_match = BITBUCKET_PIPE_RE.match(bare)
        if not pipe_match:
            continue
        ref = pipe_match.group(1)
        tail = ref.rsplit("/", 1)[-1]
        tag = tail.split(":", 1)[1] if ":" in tail else ""
        if not tag or tag.lower() == "latest":
            signals.append(
                make_signal(
                    rule_id="nhi_ci_unpinned_component",
                    file_path=path,
                    line_number=number,
                    name=ref,
                    identity_type="third-party SaaS integration",
                    source="bitbucket pipelines",
                    evidence=stripped,
                    provider="bitbucket",
                    external_access=True,
                    tags=["ci_cd", "bitbucket", "third_party", "unpinned"],
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
    if JENKINS_FILE_RE.match(name):
        return _parse_jenkins(path, text)
    if name in AZURE_PIPELINE_FILES:
        return _parse_azure_pipelines(path, text)
    if name in BITBUCKET_PIPELINE_FILES:
        return _parse_bitbucket(path, text)
    normalized = str(path).replace("\\", "/").lower()
    if ".circleci/" in normalized and name.endswith((".yml", ".yaml")):
        return _parse_circleci(path, text)
    return []
