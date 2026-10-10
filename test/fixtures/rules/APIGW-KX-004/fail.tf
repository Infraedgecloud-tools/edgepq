resource "aws_api_gateway_rest_api" "private_defaulted" {
  name = "internal"
  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [aws_vpc_endpoint.api.id]
  }
}
