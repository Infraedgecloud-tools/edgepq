resource "aws_lambda_function" "old_extension" {
  function_name = "orders"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  filename      = "orders.zip"
  layers = [
    "arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension:11",
  ]
}

resource "aws_lambda_function" "old_extension_arm" {
  function_name = "orders-arm"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  filename      = "orders.zip"
  architectures = ["arm64"]
  layers = [
    "arn:aws:lambda:eu-west-2:123456789012:layer:my-shared-lib:4",
    "arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension-Arm64:18",
  ]
}
