# No endpoint_configuration: no AWS page states the default, so the type is
# not known rather than assumed to be EDGE.
resource "aws_api_gateway_domain_name" "edge_by_default" {
  domain_name     = "www.example.com"
  certificate_arn = var.cert
}
