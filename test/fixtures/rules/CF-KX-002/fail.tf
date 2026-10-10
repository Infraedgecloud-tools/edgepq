resource "aws_cloudfront_distribution" "tls10" {
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
    minimum_protocol_version = "TLSv1.1_2016"
  }
}

# Custom certificate with no minimum stated: the provider's default is TLSv1.
resource "aws_cloudfront_distribution" "defaulted" {
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
    acm_certificate_arn = var.cert
    ssl_support_method  = "sni-only"
  }
}
