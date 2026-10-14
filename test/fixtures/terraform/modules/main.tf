# A root that calls a local module twice, once with the policy passed in and
# once left to the module's default, plus a resource whose count is decided
# at plan time and a directory nobody calls.

variable "root_policy" {
  default = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}

locals {
  plain_policy = "ELBSecurityPolicy-2016-08"
}

module "edge" {
  source     = "./edge"
  ssl_policy = var.root_policy
}

module "edge_default" {
  source = "./edge"
}

resource "aws_lb_listener" "conditional" {
  count             = var.enabled ? 1 : 0
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.plain_policy
  certificate_arn   = var.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}
