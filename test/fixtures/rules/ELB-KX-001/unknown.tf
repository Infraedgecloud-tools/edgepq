resource "aws_lb_listener" "from_variable" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# A name AWS does not document (a digit short): could not check, not a pass.
resource "aws_lb_listener" "misspelt" {
  load_balancer_arn = aws_lb.app.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-9"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# Contains "PQ" but is not a policy AWS documents.
resource "aws_lb_listener" "invented" {
  load_balancer_arn = aws_lb.app.arn
  port              = 9443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-PQ-2030-01"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# Not a documented protocol value (case matters to the API).
resource "aws_lb_listener" "lowercase_protocol" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "https"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}
