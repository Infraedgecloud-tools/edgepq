resource "aws_lambda_function" "current_extension" {
  function_name = "orders"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  filename      = "orders.zip"
  layers = [
    "arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension:123",
  ]
}

resource "aws_lambda_function" "version_19_exactly" {
  function_name = "orders-19"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  filename      = "orders.zip"
  layers = [
    "arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension-Arm64:19",
  ]
}

# No extension layer at all: the rule does not apply.
resource "aws_lambda_function" "no_layers" {
  function_name = "plain"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.13"
  filename      = "plain.zip"
}
