resource "aws_lambda_function" "layer_from_data_source" {
  function_name = "orders"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  filename      = "orders.zip"
  layers        = [data.aws_ssm_parameter.extension.value]
}
