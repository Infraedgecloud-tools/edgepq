# The way out of an edge-optimized endpoint is a regional one, which this
# rule does not apply to; APIGW-KX-001 / APIGW-KX-003 take over there.
# edgepq-fixture: passing-means-not-applicable
resource "aws_api_gateway_rest_api" "regional" {
  name = "orders"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Edge, but the default endpoint is off: nothing to find.
resource "aws_api_gateway_rest_api" "edge_without_default_endpoint" {
  name                         = "legacy"
  disable_execute_api_endpoint = true
}
