"""Tests for the Docker / Compose parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import docker


def test_should_parse_docker_and_compose_files() -> None:
    assert docker.should_parse(Path("Dockerfile")) is True
    assert docker.should_parse(Path("Dockerfile.prod")) is True
    assert docker.should_parse(Path("docker-compose.yml")) is True
    assert docker.should_parse(Path("docker-compose.override.yaml")) is True
    assert docker.should_parse(Path("compose.yaml")) is True
    assert docker.should_parse(Path("compose.yml")) is True
    assert docker.should_parse(Path("app.dockerfile")) is True
    assert docker.should_parse(Path("Dockerfile.md")) is False
    assert docker.should_parse(Path("main.tf")) is False


def test_env_literal_secret_detected_and_masked() -> None:
    text = "FROM alpine\nENV API_TOKEN=GNOC_FAKE_SECRET_DO_NOT_USE_DOCKER_112233\n"
    signals = docker.parse(Path("Dockerfile"), text)
    env = [s for s in signals if s["rule_id"] == "nhi_plaintext_env_secret"]
    assert len(env) == 1
    assert env[0]["line_number"] == 2
    assert env[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_DOCKER_112233"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in env[0]["evidence"][0]


def test_env_path_value_not_flagged() -> None:
    text = "FROM alpine\nENV SECRETS_FILE=/run/secrets/app\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_plaintext_env_secret" for s in signals)


def test_env_variable_reference_not_flagged() -> None:
    text = "FROM alpine\nENV API_KEY=$RUNTIME_API_KEY\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_plaintext_env_secret" for s in signals)


def test_arg_declaration_without_value_low_confidence() -> None:
    text = "FROM alpine\nARG GITHUB_TOKEN\n"
    signals = docker.parse(Path("Dockerfile"), text)
    env = [s for s in signals if s["rule_id"] == "nhi_plaintext_env_secret"]
    assert len(env) == 1
    assert env[0]["confidence"] == "low"
    assert env[0]["secret_value"] is None


def test_env_short_placeholder_value_not_flagged() -> None:
    text = "FROM alpine\nENV API_KEY=changeme\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_plaintext_env_secret" for s in signals)


def test_run_curl_pipe_sh_detected() -> None:
    text = "FROM alpine\nRUN curl -sSL https://get.example.com/install.sh | sh\n"
    signals = docker.parse(Path("Dockerfile"), text)
    remote = [s for s in signals if s["rule_id"] == "nhi_docker_remote_script_execution"]
    assert len(remote) == 1
    assert remote[0]["line_number"] == 2


def test_compose_command_curl_pipe_detected() -> None:
    text = """
services:
  bootstrap:
    image: alpine
    command: sh -c "wget -qO- https://get.example.com | bash"
"""
    signals = docker.parse(Path("compose.yaml"), text)
    assert any(s["rule_id"] == "nhi_docker_remote_script_execution" for s in signals)


def test_commented_curl_pipe_not_flagged() -> None:
    text = "FROM alpine\n# RUN curl -sSL https://get.example.com | sh\nRUN echo ok\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_docker_remote_script_execution" for s in signals)


def test_plain_curl_without_pipe_not_flagged() -> None:
    text = "FROM alpine\nRUN curl -f http://localhost:8080/health\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_docker_remote_script_execution" for s in signals)


def test_add_remote_url_detected() -> None:
    text = "FROM alpine\nADD https://example.com/tool.tar.gz /opt/\n"
    signals = docker.parse(Path("Dockerfile"), text)
    add = [s for s in signals if s["rule_id"] == "nhi_docker_add_remote_url"]
    assert len(add) == 1
    assert add[0]["line_number"] == 2


def test_add_local_path_not_flagged() -> None:
    text = "FROM alpine\nADD ./app /opt/app\n"
    signals = docker.parse(Path("Dockerfile"), text)
    assert not any(s["rule_id"] == "nhi_docker_add_remote_url" for s in signals)


def test_privileged_and_socket_mount_detected_in_modern_compose() -> None:
    text = """
services:
  runner:
    image: alpine
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    signals = docker.parse(Path("compose.yaml"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_docker_privileged_container" in rules
    assert "nhi_docker_socket_mount" in rules


def test_model_gateway_detected_with_line_number() -> None:
    text = """
services:
  litellm:
    image: ghcr.io/berriai/litellm:main
"""
    signals = docker.parse(Path("docker-compose.yml"), text)
    gateway = [s for s in signals if s["rule_id"] == "nhi_model_gateway_detected"]
    assert len(gateway) == 1
    assert gateway[0]["line_number"] == 3
