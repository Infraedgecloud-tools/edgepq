resource "aws_api_gateway_rest_api" "regional_pq" {
  name                 = "orders"
  security_policy      = "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09"
  endpoint_access_mode = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Default endpoint disabled: only the custom domain terminates TLS, so the
# API's own policy is moot and the rule stays silent.
resource "aws_api_gateway_rest_api" "regional_no_default_endpoint" {
  name                         = "orders-private-domain"
  disable_execute_api_endpoint = true
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_rest_api" "private_is_another_rule" {
  name = "internal"
  endpoint_configuration {
    types = ["PRIVATE"]
  }
}
