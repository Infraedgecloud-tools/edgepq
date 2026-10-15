/* What every report says the tool does not look at (PLAN.md, "Not covered in v1"). */
export const NOT_COVERED: readonly string[] = [
  'The key exchange between CloudFront and your origin.',
  'AWS Transfer Family SFTP endpoints. Post-quantum SSH policies exist for them and are a separate protocol.',
  'S3 negotiates post-quantum key exchange on the server side with nothing to configure, so there is nothing to report.',
  'Application code, including the TLS libraries and SDK versions your own software uses.',
  'Classic Load Balancers (aws_elb). No post-quantum policy exists for them; the only remedy is a move to an Application or Network Load Balancer.',
  'HTTP and WebSocket API default execute-api endpoints (aws_apigatewayv2_api). API Gateway offers them TLS_1_2 only, and nothing in the configuration changes that.',
  'KMS replica keys (aws_kms_replica_key) and keys with imported material (aws_kms_external_key). A replica of an RSA key is an RSA key; check the primary.',
  'Clouds other than AWS.',
  'Remote-module contents and input evaluation. Local module calls are read with supplied literal inputs and documented default assumptions; unresolved expressions and module instance expansion are not a complete Terraform evaluation.',
  'Which version of the Secrets Manager Lambda extension a function runs: the number in a layer ARN is a per-region publish counter, not the extension version, so it cannot be judged from configuration.',
  'Anything behind an expression the engine could not resolve. Those items are listed as could not check.',
];
