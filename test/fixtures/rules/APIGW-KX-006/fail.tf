resource "aws_apigatewayv2_domain_name" "http_api" {
  domain_name = "api.example.com"
  domain_name_configuration {
    certificate_arn = var.cert
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}
