resource "google_service_account_key" "fixture" {
  service_account_id = "projects/fixture/serviceAccounts/agent@fixture.iam.gserviceaccount.com"
}

resource "aws_iam_policy" "wide" {
  policy = jsonencode({
    Statement = [{ Action = "*", Resource = "*" }]
  })
}
