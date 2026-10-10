# A small estate with one of everything the adapters have to handle:
# a literal, a variable, a nested block, a dynamic block, a module call.

variable "policy" {
  default = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}

resource "aws_lb_listener" "classical" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.site.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_listener" "from_variable" {
  load_balancer_arn = aws_lb.app.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = var.policy
  certificate_arn   = aws_acm_certificate.site.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_listener" "plain" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_cloudfront_distribution" "site" {
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

  dynamic "ordered_cache_behavior" {
    for_each = var.behaviours
    content {
      path_pattern           = ordered_cache_behavior.value.path
      target_origin_id       = "origin"
      viewer_protocol_policy = "allow-all"
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.site.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "9.0.0"
  listeners = {
    https = { port = 443, protocol = "HTTPS", ssl_policy = "ELBSecurityPolicy-2016-08" }
  }
}
