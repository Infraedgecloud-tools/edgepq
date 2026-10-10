resource "aws_api_gateway_domain_name" "edge_explicit" {
  domain_name     = "edge.example.com"
  certificate_arn = var.cert
  security_policy = "TLS_1_2"
  endpoint_configuration {
    types = ["EDGE"]
  }
}
