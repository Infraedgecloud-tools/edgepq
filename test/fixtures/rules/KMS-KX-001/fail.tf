resource "aws_kms_key" "rsa_explicit_usage" {
  description              = "Encrypts customer documents with the public key"
  customer_master_key_spec = "RSA_4096"
  key_usage                = "ENCRYPT_DECRYPT"
}

# key_usage absent: the default is ENCRYPT_DECRYPT.
resource "aws_kms_key" "rsa_default_usage" {
  description              = "Encryption key"
  customer_master_key_spec = "RSA_2048"
}

# SM2 (China Regions) is classical public-key encryption too.
resource "aws_kms_key" "sm2" {
  customer_master_key_spec = "SM2"
  key_usage                = "ENCRYPT_DECRYPT"
}
