# GAP-01 / GAP-02: customer-owned key for PHI (SOC 2 CC6.1)
resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI key (uploads bucket + intake table)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

# Evidence key: separate from the PHI key (SOC 2 CC6.1 / separation of duties)
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "evidence_key" {
  statement {
    sid       = "AccountAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt"]
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "Acme Health evidence vault and audit log key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.evidence_key.json
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence.key_id
}
