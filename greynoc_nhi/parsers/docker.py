"""Docker and Compose parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("docker-compose") or path.suffix.lower() in {".dockerfile"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"^(ENV|ARG)\s+.*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)", stripped, re.I):
            signals.append(
                make_signal(
                    rule_id="nhi_plaintext_env_secret",
                    file_path=path,
                    line_number=number,
                    name="Docker secret variable",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    tags=["docker", "plaintext_secret"],
                )
            )
        if "privileged:" in stripped.lower() and "true" in stripped.lower():
            signals.append(
                make_signal(
                    rule_id="nhi_docker_privileged_container",
                    file_path=path,
                    line_number=number,
                    name="Privileged container",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    admin_access=True,
                    tags=["docker", "privileged"],
                )
            )
        if "/var/run/docker.sock" in stripped:
            signals.append(
                make_signal(
                    rule_id="nhi_docker_socket_mount",
                    file_path=path,
                    line_number=number,
                    name="Docker socket mount",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    admin_access=True,
                    tags=["docker", "host_access"],
                )
            )
    return signals
