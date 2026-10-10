# The way out of an edge-optimized endpoint is a regional one, which this
# rule does not apply to; APIGW-KX-001 / APIGW-KX-003 take over there.
# edgepq-fixture: passing-means-not-applicable
resource "aws_api_gateway_domain_name" "regional" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
  endpoint_access_mode     = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
