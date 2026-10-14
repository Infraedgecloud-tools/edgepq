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

# TLS 1.3-only policies: no post-quantum policy keeps TLS 1.3 alone, so the
# fix re-admits TLS 1.2 with forward-secret suites and is marked review.
resource "aws_api_gateway_rest_api" "regional_tls13_only" {
  name                 = "orders-tls13"
  security_policy      = "SecurityPolicy_TLS13_1_3_2025_09"
  endpoint_access_mode = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_rest_api" "regional_tls13_fips" {
  name                 = "orders-fips"
  security_policy      = "SecurityPolicy_TLS13_1_3_FIPS_2025_09"
  endpoint_access_mode = "BASIC"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
