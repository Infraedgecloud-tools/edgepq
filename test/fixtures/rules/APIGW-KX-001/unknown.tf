resource "aws_api_gateway_domain_name" "from_variable" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = var.policy
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Not a policy AWS documents for a regional domain.
resource "aws_api_gateway_domain_name" "invented" {
  domain_name              = "api2.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_PQ_2099"
  endpoint_access_mode     = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# The developer guide's spelling of the FIPS post-quantum policy; the API
# reference, which the service validates against, spells it without PFS.
resource "aws_api_gateway_domain_name" "guide_spelling" {
  domain_name              = "fips.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09"
  endpoint_access_mode     = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
