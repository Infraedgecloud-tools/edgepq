# The way out is a certificate of your own, which this rule does not apply
# to; CF-KX-002 takes over there.
# edgepq-fixture: passing-means-not-applicable
resource "aws_cloudfront_distribution" "own_certificate" {
  enabled = true
  origin {
    domain_name = "origin.example.com"
    origin_id   = "origin"
  }
  default_cache_behavior {
    target_origin_id       = "origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate {
    acm_certificate_arn      = var.cert
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
