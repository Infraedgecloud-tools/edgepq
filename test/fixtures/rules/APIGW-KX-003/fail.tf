resource "aws_api_gateway_rest_api" "regional_defaulted" {
  name = "orders"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_rest_api" "regional_tls12" {
  name            = "orders-v2"
  security_policy = "TLS_1_2"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
