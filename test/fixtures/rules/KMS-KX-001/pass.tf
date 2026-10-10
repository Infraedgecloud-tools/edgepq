# Both attributes absent: a symmetric AES-256-GCM key.
resource "aws_kms_key" "symmetric_default" {
  description = "Data at rest"
}

resource "aws_kms_key" "symmetric_explicit" {
  description              = "Data at rest"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
}

# Signing keys are another rule's business.
resource "aws_kms_key" "rsa_signing" {
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
