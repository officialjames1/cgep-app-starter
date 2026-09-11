variable "github_org"  { type = string }
variable "github_repo" { type = string }

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:officialjames1@108308389/cgep-app-starter@1361942311:*" }
      }
    }]
  })
}

# NOTE: broadened from ReadOnlyAccess to AdministratorAccess so this role can
# actually run terraform apply (KMS, S3, DynamoDB, Lambda, IAM, CloudTrail,
# Security Hub, API Gateway, VPC) plus read/write the remote state backend
# (S3 state bucket + DynamoDB lock table). Security here comes from WHO can
# assume this role — locked to this exact repo via the OIDC trust condition
# above — not from what the role can do once assumed. A production system
# would scope this down further (e.g. via IAM Access Analyzer policy
# generation from real apply activity); deferred here given capstone scope.
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }
