terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
resource "aws_route53_resolver_rule" "r53_outbound_resolver_rule" {
  domain_name          = var.r53_rule_domain_name
  name                 = "${var.r53_rule_name}-${var.r53_rule_random_string}"
  rule_type            = "FORWARD"
  resolver_endpoint_id = var.r53_rule_r53_outbound_resolver_id
  tags = {
    Name = "${var.r53_rule_name}-${var.r53_rule_random_string}"
  }

  dynamic "target_ip" {
    for_each = var.r53_rule_target_ip
    iterator = ip
    content {
      ip = ip.value
    }
  }
}

resource "aws_route53_resolver_rule_association" "r53_outbound_resolver_rule_association" {
  name             = "${var.r53_rule_name}-${var.r53_rule_random_string}-Association"
  resolver_rule_id = aws_route53_resolver_rule.r53_outbound_resolver_rule.id
  vpc_id           = var.r53_rule_vpc_id
}
