resource "aws_api_gateway_domain_name" "pq" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
  endpoint_access_mode     = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_domain_name" "fips_pq_private" {
  domain_name              = "internal.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09"
  endpoint_access_mode     = "STRICT"
  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

# Edge-optimized: a different rule's business, this one stays silent.
resource "aws_api_gateway_domain_name" "edge" {
  domain_name     = "edge.example.com"
  certificate_arn = var.cert
  endpoint_configuration {
    types = ["EDGE"]
  }
}
