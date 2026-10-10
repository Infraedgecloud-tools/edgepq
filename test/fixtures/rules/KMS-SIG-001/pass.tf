resource "aws_kms_key" "mldsa" {
  description              = "Firmware signing root"
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "mldsa_87" {
  customer_master_key_spec = "ML_DSA_87"
  key_usage                = "SIGN_VERIFY"
}

# Not a signing key: the rule stays silent.
resource "aws_kms_key" "hmac" {
  customer_master_key_spec = "HMAC_256"
  key_usage                = "GENERATE_VERIFY_MAC"
}

resource "aws_kms_key" "symmetric" {
  description = "Data at rest"
}
