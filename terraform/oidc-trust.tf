# GitHub Actions login (OIDC). SOC 2 CC6.3: least privilege, split plan/apply.
# The GitHub OIDC provider already exists in this account (created in Lab 4.3),
# so we reference it instead of creating a second one.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  gh_org  = "grcEngBeth"
  gh_repo = "cgep-capstone"
}

# PLAN role: any pull request in this repo, read-only
resource "aws_iam_role" "plan" {
  name = "${local.name_prefix}-gate-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${local.gh_org}/${local.gh_repo}:*",
            "repo:${local.gh_org}@*/${local.gh_repo}@*:*",
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# APPLY role: only workflow runs on the main branch
resource "aws_iam_role" "apply" {
  name = "${local.name_prefix}-gate-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${local.gh_org}/${local.gh_repo}:ref:refs/heads/main",
            "repo:${local.gh_org}@*/${local.gh_repo}@*:ref:refs/heads/main",
          ]
        }
      }
    }]
  })
}

# Trade-off (see WRITEUP): admin keeps a 30-day build simple; production would
# use a custom policy scoped to this stack.
resource "aws_iam_role_policy_attachment" "apply_admin" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "plan_role_arn" {
  value = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  value = aws_iam_role.apply.arn
}
