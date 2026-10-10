resource "aws_acmpca_certificate_authority" "mldsa_root" {
  type = "ROOT"
  certificate_authority_configuration {
    key_algorithm     = "ML_DSA_65"
    signing_algorithm = "ML_DSA_65"
    subject {
      common_name = "Example Code Signing Root"
    }
  }
}
