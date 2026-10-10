resource "aws_api_gateway_rest_api" "edge_by_default" {
  name = "legacy"
}

resource "aws_api_gateway_rest_api" "edge_explicit" {
  name            = "legacy-2"
  security_policy = "SecurityPolicy_TLS13_2025_EDGE"
  endpoint_access_mode = "BASIC"
  endpoint_configuration {
    types = ["EDGE"]
  }
}
