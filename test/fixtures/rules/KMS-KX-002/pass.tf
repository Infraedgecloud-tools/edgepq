# edgepq-fixture: no-passing-configuration-exists
# KMS offers no post-quantum key agreement spec; the way out is to stop doing
# key agreement in KMS, which this rule no longer sees.
resource "aws_kms_key" "symmetric" {
  description = "Data at rest"
}

resource "aws_kms_key" "signing" {
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}
