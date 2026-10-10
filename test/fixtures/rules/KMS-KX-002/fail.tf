resource "aws_kms_key" "ecdh" {
  description              = "Derives shared secrets for a partner integration"
  customer_master_key_spec = "ECC_NIST_P384"
  key_usage                = "KEY_AGREEMENT"
}
