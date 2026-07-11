"""Tests for the Kubernetes manifest parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import kubernetes


def test_should_parse_any_yaml_file() -> None:
    assert kubernetes.should_parse(Path("k8s-deployment.yaml")) is True
    assert kubernetes.should_parse(Path("pod.yaml")) is True
    assert kubernetes.should_parse(Path("cronjob.yml")) is True
    assert kubernetes.should_parse(Path("manifests/base/rbac.yaml")) is True
    assert kubernetes.should_parse(Path("main.tf")) is False


def test_non_manifest_yaml_exits_early() -> None:
    text = """
services:
  app:
    image: alpine
    privileged: true
"""
    assert kubernetes.parse(Path("docker-compose.yaml"), text) == []


def test_privileged_pod_detected_in_generic_filename() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata:
  name: runner
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
"""
    signals = kubernetes.parse(Path("pod.yaml"), text)
    privileged = [s for s in signals if s["rule_id"] == "nhi_docker_privileged_container"]
    assert len(privileged) == 1
    assert privileged[0]["line_number"] == 10


def test_cluster_admin_binding_line_number() -> None:
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
roleRef:
  name: cluster-admin
"""
    signals = kubernetes.parse(Path("rbac.yaml"), text)
    admin = [s for s in signals if s["rule_id"] == "nhi_kubernetes_cluster_admin"]
    assert len(admin) == 1
    assert admin[0]["line_number"] == 5


def test_env_literal_secret_detected_and_masked() -> None:
    text = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: DB_PASSWORD
              value: GNOC_FAKE_SECRET_DO_NOT_USE_K8SENV_112233
            - name: LOG_LEVEL
              value: debug
"""
    signals = kubernetes.parse(Path("deployment.yaml"), text)
    env = [s for s in signals if s["rule_id"] == "nhi_kubernetes_env_plaintext_secret"]
    assert len(env) == 1
    assert env[0]["name"] == "DB_PASSWORD"
    assert env[0]["line_number"] == 11
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in env[0]["evidence"][0]


def test_env_secret_key_ref_not_flagged() -> None:
    text = """
apiVersion: apps/v1
kind: Deployment
spec:
  containers:
    - name: app
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
"""
    signals = kubernetes.parse(Path("deployment.yaml"), text)
    assert not any(s["rule_id"] == "nhi_kubernetes_env_plaintext_secret" for s in signals)


def test_env_variable_reference_not_flagged() -> None:
    text = """
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      env:
        - name: API_TOKEN
          value: $(RUNTIME_TOKEN)
"""
    signals = kubernetes.parse(Path("pod.yaml"), text)
    assert not any(s["rule_id"] == "nhi_kubernetes_env_plaintext_secret" for s in signals)


def test_host_namespace_and_root_user_detected() -> None:
    text = """
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  securityContext:
    runAsUser: 0
"""
    signals = kubernetes.parse(Path("pod.yaml"), text)
    overprivileged = [s for s in signals if s["rule_id"] == "nhi_overprivileged_nhi"]
    assert len(overprivileged) == 2


def test_kind_secret_and_automount_still_detected() -> None:
    text = """
apiVersion: v1
kind: Secret
metadata:
  name: token
---
apiVersion: v1
kind: ServiceAccount
automountServiceAccountToken: true
"""
    signals = kubernetes.parse(Path("k8s-secret.yaml"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_secret_leakage" in rules
    assert "nhi_kubernetes_automount_token" in rules
    secret = next(s for s in signals if s["rule_id"] == "nhi_secret_leakage")
    assert secret["line_number"] == 3
