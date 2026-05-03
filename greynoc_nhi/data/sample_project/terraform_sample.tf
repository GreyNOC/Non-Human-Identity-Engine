resource "aws_iam_policy" "adminish" {
  name = "fake-adminish-policy"
  policy = jsonencode({
    Statement = [{
      Action = "*"
      Resource = "*"
      Effect = "Allow"
    }]
  })
}

variable "secret_key" {
  default = "FAKE_AWS_SECRET_DO_NOT_USE_TERRAFORM"
}
