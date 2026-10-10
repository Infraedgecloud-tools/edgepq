resource "aws_kms_key" "spec_from_variable" {
  customer_master_key_spec = var.key_spec
  key_usage                = "ENCRYPT_DECRYPT"
}

# Not a spec the API accepts (case matters); the provider rejects it at plan.
resource "aws_kms_key" "lowercase" {
  customer_master_key_spec = "rsa_2048"
  key_usage                = "ENCRYPT_DECRYPT"
}
