# There is no passing HTTP API domain today: every aws_apigatewayv2_domain_name
# fails this rule until API Gateway offers a PQ policy for HTTP and WebSocket
# APIs. The passing fixture is therefore empty of that resource type, and the
# harness accepts a pass file that contains nothing the rule applies to only
# when the file says so with this marker:
# edgepq-fixture: no-passing-configuration-exists
resource "aws_api_gateway_domain_name" "rest_instead" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
  endpoint_access_mode     = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
