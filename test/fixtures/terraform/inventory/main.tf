# One of each resource type the CBOM inventories, plus cases for each default.
resource "aws_lb_listener" "alb_https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/app/x/1"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}
resource "aws_alb_listener" "alb_default_policy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/app/x/1"
  port              = 443
  protocol          = "HTTPS"
}
resource "aws_lb_listener" "nlb_tls_unresolved" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/net/x/1"
  port              = 443
  protocol          = "TLS"
  ssl_policy        = var.policy
}
resource "aws_lb_listener" "plain_http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/app/x/1"
  port              = 80
  protocol          = "HTTP"
}
resource "aws_api_gateway_domain_name" "domain_pq" {
  domain_name              = "api.example.com"
  regional_certificate_arn = var.cert
  security_policy          = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
  endpoint_access_mode     = "BASIC"
}
resource "aws_api_gateway_domain_name" "domain_default" {
  domain_name              = "old.example.com"
  regional_certificate_arn = var.cert
}
resource "aws_api_gateway_rest_api" "edge_default" {
  name = "edge-default"
}
resource "aws_api_gateway_rest_api" "private" {
  name = "private"
  endpoint_configuration {
    types = ["PRIVATE"]
  }
}
resource "aws_api_gateway_rest_api" "no_execute_api" {
  name                         = "no-execute-api"
  disable_execute_api_endpoint = true
}
resource "aws_apigatewayv2_domain_name" "v2" {
  domain_name = "v2.example.com"
  domain_name_configuration {
    certificate_arn = var.cert
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
}
resource "aws_kms_key" "symmetric" {
  description = "default spec"
}
resource "aws_kms_key" "rsa_encrypt" {
  customer_master_key_spec = "RSA_3072"
}
resource "aws_kms_key" "rsa_sign" {
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "ecdsa" {
  customer_master_key_spec = "ECC_NIST_P384"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "ecdh" {
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "KEY_AGREEMENT"
}
resource "aws_kms_key" "ed25519" {
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "hmac" {
  customer_master_key_spec = "HMAC_384"
  key_usage                = "GENERATE_VERIFY_MAC"
}
resource "aws_kms_key" "mldsa" {
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "sm2" {
  customer_master_key_spec = "SM2"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "unresolved" {
  customer_master_key_spec = var.spec
}
resource "aws_acm_certificate" "default_key" {
  domain_name       = "www.example.com"
  validation_method = "DNS"
}
resource "aws_acm_certificate" "ec" {
  domain_name       = "ec.example.com"
  validation_method = "DNS"
  key_algorithm     = "EC_prime256v1"
}
resource "aws_acm_certificate" "imported" {
  certificate_body = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
  private_key      = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
}
resource "aws_acmpca_certificate_authority" "classical" {
  type = "ROOT"
  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"
    subject {
      common_name = "example.com"
    }
  }
}
resource "aws_acmpca_certificate_authority" "mldsa" {
  type = "ROOT"
  certificate_authority_configuration {
    key_algorithm     = "ML_DSA_65"
    signing_algorithm = "ML_DSA_65"
    subject {
      common_name = "pq.example.com"
    }
  }
}
resource "aws_s3_bucket" "ignored" {
  bucket = "nothing-to-inventory"
}
