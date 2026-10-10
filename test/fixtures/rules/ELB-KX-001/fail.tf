# Explicit classical policy on an ALB listener.
resource "aws_lb_listener" "explicit_classical" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# No policy at all: Terraform creates it with ELBSecurityPolicy-2016-08.
resource "aws_lb_listener" "defaulted" {
  load_balancer_arn = aws_lb.app.arn
  port              = 8443
  protocol          = "HTTPS"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# An NLB TLS listener on a FIPS policy without PQ.
resource "aws_lb_listener" "nlb_fips" {
  load_balancer_arn = aws_lb.net.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tcp.arn
  }
}
