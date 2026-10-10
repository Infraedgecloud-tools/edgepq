resource "aws_api_gateway_domain_name" "edge_explicit" {
  domain_name     = "edge.example.com"
  certificate_arn = var.cert
  security_policy = "TLS_1_2"
  endpoint_configuration {
    types = ["EDGE"]
  }
}

# No endpoint_configuration: the provider defaults the type to EDGE.
resource "aws_api_gateway_domain_name" "edge_by_default" {
  domain_name     = "www.example.com"
  certificate_arn = var.cert
}
