resource "aws_api_gateway_domain_name" "regional_legacy" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "TLS_1_2"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# No security_policy: API Gateway assigns TLS_1_2 to a domain name.
resource "aws_api_gateway_domain_name" "private_defaulted" {
  domain_name              = "internal.example.com"
  regional_certificate_arn = var.cert
  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

resource "aws_api_gateway_domain_name" "enhanced_but_classical" {
  domain_name              = "strict.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_3_2025_09"
  endpoint_access_mode     = "STRICT"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
