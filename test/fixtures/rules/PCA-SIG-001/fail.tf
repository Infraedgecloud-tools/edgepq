resource "aws_acmpca_certificate_authority" "rsa_root" {
  type = "ROOT"
  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"
    subject {
      common_name = "Example Root CA"
    }
  }
}

resource "aws_acmpca_certificate_authority" "ec_sub" {
  type = "SUBORDINATE"
  certificate_authority_configuration {
    key_algorithm     = "EC_prime256v1"
    signing_algorithm = "SHA256WITHECDSA"
    subject {
      common_name = "Example Issuing CA"
    }
  }
}
