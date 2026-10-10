resource "aws_kms_key" "spec_from_variable" {
  customer_master_key_spec = var.key_spec
  key_usage                = "ENCRYPT_DECRYPT"
}
