"""Parser for package-publishing credential files.

Catches structurally-named credential files for the major package registries.
These tokens often have massive supply-chain blast radius - publishing a
malicious version of a private package, for example - so they warrant a
dedicated detector even when individual token formats already match the
modern_saas regex pack.

Files covered:

* `.npmrc` - npm `_authToken`, `_password`
* `.pypirc` - PyPI tokens, password=, [pypi] / [testpypi] sections
* `.cargo/credentials` and `.cargo/credentials.toml` - Cargo registry tokens
* `.gradle/gradle.properties` and `.gradle/init.gradle` - Maven / Artifactory / Nexus
* `.netrc` - generic machine/login/password entries
"""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

NPMRC_TOKEN_RE = re.compile(r"^(//[^/\s]+/:_(?:authToken|password))\s*=\s*(.+)$", re.IGNORECASE)
PYPIRC_KV_RE = re.compile(r"^\s*(username|password)\s*=\s*(.+)$", re.IGNORECASE)
CARGO_TOKEN_RE = re.compile(r"^\s*token\s*=\s*['\"]?([^'\"\n]+)['\"]?", re.IGNORECASE)
GRADLE_KV_RE = re.compile(
    r"^\s*([A-Za-z][\w.\-]*(?:password|token|secret|api[_-]?key|credential|auth)[\w.\-]*)\s*=\s*(.+)$",
    re.IGNORECASE,
)


def _path_normalized(path: Path) -> str:
    return str(path).replace("\\", "/").lower()


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    normalized = _path_normalized(path)
    if name in {".npmrc", ".pypirc", ".netrc"}:
        return True
    if normalized.endswith(".cargo/credentials") or normalized.endswith(".cargo/credentials.toml"):
        return True
    if normalized.endswith(".cargo/config.toml") or normalized.endswith(".cargo/config"):
        return True
    if normalized.endswith(".gradle/init.gradle") or normalized.endswith(".gradle/gradle.properties"):
        return True
    if name == "gradle.properties":
        return True
    return False


def _parse_npmrc(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith(";"):
            continue
        match = NPMRC_TOKEN_RE.match(clean)
        if not match:
            continue
        registry_key = match.group(1)
        value = match.group(2).strip().strip("'\"")
        if not value or value.startswith("$"):
            continue
        if not looks_like_secret(value):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_npm_registry_token_in_npmrc",
                file_path=path,
                line_number=number,
                name=registry_key,
                identity_type="api_key",
                source=".npmrc",
                evidence=clean,
                secret_value=value,
                provider="npm",
                external_access=True,
                tags=["npm", "package_registry", "publish_token", "supply_chain"],
                confidence="high",
            )
        )
    return signals


def _parse_pypirc(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    section = ""
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if clean.startswith("[") and clean.endswith("]"):
            section = clean.strip("[]").lower()
            continue
        match = PYPIRC_KV_RE.match(clean)
        if not match:
            continue
        if match.group(1).lower() != "password":
            continue
        value = match.group(2).strip().strip("'\"")
        if not value or value.startswith("$"):
            continue
        if not looks_like_secret(value) and not value.startswith("pypi-"):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_pypi_token_in_pypirc",
                file_path=path,
                line_number=number,
                name=f"[{section}] password" if section else "password",
                identity_type="api_key",
                source=".pypirc",
                evidence=clean,
                secret_value=value,
                provider="pypi",
                external_access=True,
                tags=["pypi", "package_registry", "publish_token", "supply_chain"],
                confidence="high",
            )
        )
    return signals


def _parse_cargo(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        match = CARGO_TOKEN_RE.match(clean)
        if not match:
            continue
        value = match.group(1).strip()
        if not value or not looks_like_secret(value):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_cargo_registry_token",
                file_path=path,
                line_number=number,
                name="cargo registry token",
                identity_type="api_key",
                source=".cargo",
                evidence=clean,
                secret_value=value,
                provider="cargo",
                external_access=True,
                tags=["cargo", "package_registry", "publish_token", "supply_chain"],
                confidence="high",
            )
        )
    return signals


def _parse_gradle(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("//"):
            continue
        match = GRADLE_KV_RE.match(clean)
        if not match:
            continue
        key = match.group(1)
        value = match.group(2).strip().strip("'\"")
        if not value or value.startswith("$") or value.startswith("System.getenv"):
            continue
        if not looks_like_secret(value):
            continue
        signals.append(
            make_signal(
                rule_id="nhi_gradle_repository_credential",
                file_path=path,
                line_number=number,
                name=key,
                identity_type="api_key",
                source="gradle",
                evidence=clean,
                secret_value=value,
                provider="gradle",
                external_access=True,
                tags=["gradle", "package_registry", "publish_token", "supply_chain"],
                confidence="high",
            )
        )
    return signals


def _parse_netrc(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    machine = ""
    machine_line = 0
    pending_login = ""
    for number, line in enumerate(text.splitlines(), 1):
        tokens = line.strip().split()
        i = 0
        while i < len(tokens):
            token = tokens[i].lower()
            if token == "machine" and i + 1 < len(tokens):
                machine = tokens[i + 1]
                machine_line = number
                pending_login = ""
                i += 2
                continue
            if token == "login" and i + 1 < len(tokens):
                pending_login = tokens[i + 1]
                i += 2
                continue
            if token == "password" and i + 1 < len(tokens):
                value = tokens[i + 1]
                if looks_like_secret(value):
                    signals.append(
                        make_signal(
                            rule_id="nhi_netrc_credential",
                            file_path=path,
                            line_number=number or machine_line,
                            name=f"{machine}:{pending_login}" if machine else "netrc password",
                            identity_type="api_key",
                            source=".netrc",
                            evidence=line.strip(),
                            secret_value=value,
                            provider="netrc",
                            external_access=True,
                            tags=["netrc", "package_registry", "supply_chain"],
                            confidence="high",
                        )
                    )
                i += 2
                continue
            i += 1
    return signals


def parse(path: Path, text: str) -> list[Signal]:
    name = path.name.lower()
    normalized = _path_normalized(path)
    if name == ".npmrc":
        return _parse_npmrc(path, text)
    if name == ".pypirc":
        return _parse_pypirc(path, text)
    if normalized.endswith(".cargo/credentials") or normalized.endswith(".cargo/credentials.toml") or normalized.endswith(".cargo/config.toml") or normalized.endswith(".cargo/config"):
        return _parse_cargo(path, text)
    if normalized.endswith(".gradle/init.gradle") or normalized.endswith(".gradle/gradle.properties") or name == "gradle.properties":
        return _parse_gradle(path, text)
    if name == ".netrc":
        return _parse_netrc(path, text)
    return []
