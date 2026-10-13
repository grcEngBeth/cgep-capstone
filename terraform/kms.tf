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
