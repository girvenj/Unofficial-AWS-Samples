terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

locals {
  r53_ports = [
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "TCP"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "UDP"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
}

module "vpc_resolver_security_group" {
  source      = "../vpc-security-group-egress"
  name        = "${var.r53_resolver_name}-Resolver-Security-Group-${var.r53_resolver_random_string}"
  description = "${var.r53_resolver_name} Resolver Security Group"
  vpc_id      = var.r53_resolver_vpc_id
  ports       = local.r53_ports
}

resource "aws_route53_resolver_endpoint" "r53_outbound_resolver" {
  name               = "${var.r53_resolver_name}-${var.r53_resolver_random_string}"
  direction          = "OUTBOUND"
  security_group_ids = [module.vpc_resolver_security_group.sg_id]
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[0]
  }
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[1]
  }
  tags = {
    Name = "${var.r53_resolver_name}-${var.r53_resolver_random_string}"
  }
}
