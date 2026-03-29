resource "aws_iam_policy" "admin_policy" {
  name = "full-admin-policy"

  # VULNERABILITY: Wildcard actions on all resources
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.app_role.name
  # VULNERABILITY: AdministratorAccess policy attached
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# VULNERABILITY: Inline IAM policy
resource "aws_iam_role_policy" "inline_policy" {
  name = "inline-policy"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:*", "iam:*"]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY: Weak password policy
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 6
}
