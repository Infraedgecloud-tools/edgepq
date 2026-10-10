# The least-privilege role EdgePQ assumes to scan an account. Read-only: every
# action below is a List, Describe or Get, and the policy names them one by one
# rather than using a wildcard, so a reviewer can tick each off against
# edgepq/src/aws/collectors/.
#
# Apply this in every account to be scanned. The scanner is run from one
# place (a laptop, a CI job) whose principal is `var.trusted_principal_arn`,
# and it assumes `edgepq-readonly` in each target account.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }
    dynamic "condition" {
      for_each = var.external_id == null ? [] : [var.external_id]
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

data "aws_iam_policy_document" "readonly" {
  statement {
    sid = "Inventory"
    actions = [
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeListeners",
      "cloudfront:ListDistributions",
      "kms:ListKeys",
      "kms:DescribeKey",
      "acm:ListCertificates",
      "acm-pca:ListCertificateAuthorities",
      "lambda:ListFunctions",
      "ec2:DescribeRegions",
    ]
    resources = ["*"]
  }

  # API Gateway authorises HTTP verbs against resource paths. GET on the
  # domain names and REST API collections (and their children, which the
  # paginated listing returns) is what GetDomainNames and GetRestApis need.
  statement {
    sid     = "ApiGatewayRead"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${data.aws_partition.current.partition}:apigateway:*::/domainnames",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/domainnames/*",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/restapis",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/restapis/*",
    ]
  }

  # The client-readiness sample reads the 90-day event history. Not a trail,
  # no S3 bucket, no cost.
  dynamic "statement" {
    for_each = var.cloudtrail_sample ? [1] : []
    content {
      sid       = "ClientSample"
      actions   = ["cloudtrail:LookupEvents"]
      resources = ["*"]
    }
  }
}

data "aws_partition" "current" {}

resource "aws_iam_role" "edgepq" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  description          = "Read-only inventory for EdgePQ post-quantum readiness scans"
  tags                 = var.tags
}

resource "aws_iam_role_policy" "readonly" {
  name   = "edgepq-readonly"
  role   = aws_iam_role.edgepq.id
  policy = data.aws_iam_policy_document.readonly.json
}
