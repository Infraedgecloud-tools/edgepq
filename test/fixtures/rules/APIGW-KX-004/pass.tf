resource "aws_api_gateway_rest_api" "private_pq" {
  name                 = "internal"
  security_policy      = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
  endpoint_access_mode = "STRICT"
  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [aws_vpc_endpoint.api.id]
  }
}

resource "aws_api_gateway_rest_api" "regional_is_another_rule" {
  name = "orders"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
