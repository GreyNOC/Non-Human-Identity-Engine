"""Tests for the Terraform (.tf) parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import terraform


def test_should_parse_tf_files() -> None:
    assert terraform.should_parse(Path("main.tf")) is True
    assert terraform.should_parse(Path("terraform.tfstate")) is False
    assert terraform.should_parse(Path("values.yaml")) is False


def test_service_account_key_does_not_abort_credential_scan() -> None:
    # Regression: the whole-file service_account_key check used to break out
    # of the line loop on iteration 1, hiding later hardcoded credentials.
    text = """resource "google_service_account_key" "fixture" {
  service_account_id = "projects/fixture/serviceAccounts/agent@fixture.iam.gserviceaccount.com"
}

provider "aws" {
  secret_key = "GNOC_FAKE_SECRET_DO_NOT_USE_TF_112233"
}
"""
    signals = terraform.parse(Path("main.tf"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_service_account_key_file" in rules
    assert "nhi_cloud_key_detected" in rules
    key_signal = next(s for s in signals if s["rule_id"] == "nhi_cloud_key_detected")
    assert key_signal["line_number"] == 6
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in key_signal["evidence"][0]
    sak_signal = next(s for s in signals if s["rule_id"] == "nhi_service_account_key_file")
    assert sak_signal["line_number"] == 1


def test_cors_wildcard_not_flagged_as_admin_policy() -> None:
    text = """
resource "aws_s3_bucket_cors_configuration" "site" {
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET"]
    allowed_origins = ["https://example.com"]
  }
}
"""
    signals = terraform.parse(Path("cors.tf"), text)
    assert not any(s["rule_id"] == "nhi_cloud_admin_policy" for s in signals)


def test_jsonencode_wildcard_policy_flagged() -> None:
    text = """
resource "aws_iam_policy" "wide" {
  policy = jsonencode({
    Statement = [{ Action = "*", Resource = "*" }]
  })
}
"""
    signals = terraform.parse(Path("iam.tf"), text)
    admin = [s for s in signals if s["rule_id"] == "nhi_cloud_admin_policy"]
    assert len(admin) == 1
    assert admin[0]["line_number"] == 4


def test_json_policy_wildcard_flagged() -> None:
    text = 'policy = <<EOF\n{"Statement": [{"Action": "*", "Resource": "arn:aws:s3:::x"}]}\nEOF\n'
    signals = terraform.parse(Path("iam.tf"), text)
    assert any(s["rule_id"] == "nhi_cloud_admin_policy" for s in signals)


def test_hcl_actions_attribute_wildcard_flagged() -> None:
    text = """
data "aws_iam_policy_document" "wide" {
  statement {
    actions = ["*"]
  }
}
"""
    signals = terraform.parse(Path("iam.tf"), text)
    assert any(s["rule_id"] == "nhi_cloud_admin_policy" for s in signals)


def test_administrator_access_arn_flagged() -> None:
    text = """
resource "aws_iam_role_policy_attachment" "admin" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""
    signals = terraform.parse(Path("iam.tf"), text)
    assert any(s["rule_id"] == "nhi_cloud_admin_policy" for s in signals)


def test_provider_token_and_password_detected() -> None:
    text = """
provider "github" {
  token = "GNOC_FAKE_SECRET_DO_NOT_USE_GH_314159"
}

resource "aws_db_instance" "db" {
  password = "GNOC_FAKE_SECRET_DO_NOT_USE_DB_271828"
}
"""
    signals = terraform.parse(Path("providers.tf"), text)
    creds = [s for s in signals if s["rule_id"] == "nhi_cloud_key_detected"]
    assert len(creds) == 2
    for signal in creds:
        assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in signal["evidence"][0]


def test_var_interpolated_credential_not_flagged() -> None:
    text = """
provider "aws" {
  secret_key = "${var.aws_secret}"
  token      = "$TOKEN_FROM_ENV"
}
"""
    signals = terraform.parse(Path("providers.tf"), text)
    assert not any(s["rule_id"] == "nhi_cloud_key_detected" for s in signals)


def test_short_non_secret_value_not_flagged() -> None:
    text = 'resource "x" "y" {\n  token_type = "Bearer12"\n}\n'
    signals = terraform.parse(Path("main.tf"), text)
    assert not any(s["rule_id"] == "nhi_cloud_key_detected" for s in signals)


def test_remote_exec_provisioner_detected() -> None:
    text = """
resource "aws_instance" "web" {
  provisioner "remote-exec" {
    inline = [
      "curl -sSL https://get.example.com/install.sh | sh",
    ]
  }
}
"""
    signals = terraform.parse(Path("main.tf"), text)
    provisioners = [s for s in signals if s["rule_id"] == "nhi_terraform_provisioner_exec"]
    assert len(provisioners) == 1
    assert provisioners[0]["line_number"] == 3
    assert provisioners[0]["confidence"] == "high"
    assert "remote_script" in provisioners[0]["tags"]


def test_local_exec_provisioner_detected_without_remote_fetch() -> None:
    text = """
resource "null_resource" "notify" {
  provisioner "local-exec" {
    command = "echo done"
  }
}
"""
    signals = terraform.parse(Path("main.tf"), text)
    provisioners = [s for s in signals if s["rule_id"] == "nhi_terraform_provisioner_exec"]
    assert len(provisioners) == 1
    assert provisioners[0]["confidence"] == "medium"
