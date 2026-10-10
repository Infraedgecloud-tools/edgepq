resource "aws_kms_key" "rsa_sign" {
  customer_master_key_spec = "RSA_3072"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "ecdsa_sign" {
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "ed25519_sign" {
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
}
