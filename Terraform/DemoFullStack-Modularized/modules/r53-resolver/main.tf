terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_vpc" "main" {
  id = var.r53_resolver_vpc_id
}

locals {
  r53_inbound_ports = [
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]

  r53_outbound_ports = [
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "TCP"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "UDP"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "vpc_outbound_resolver_security_group" {
  source      = "../vpc-security-group-egress"
  name        = "${var.r53_resolver_name}-R53-Outbound-Resolver-Security-Group-${var.r53_resolver_random_string}"
  description = "${var.r53_resolver_name} R53 Outbound Resolver Security Group"
  vpc_id      = var.r53_resolver_vpc_id
  ports       = local.r53_outbound_ports
}

resource "aws_route53_resolver_endpoint" "r53_outbound_resolver" {
  name               = "${var.r53_resolver_name}-R53-Outbound-Resolver-${var.r53_resolver_random_string}"
  direction          = "OUTBOUND"
  security_group_ids = [module.vpc_outbound_resolver_security_group.sg_id]
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[0]
  }
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[1]
  }
  tags = {
    Name = "${var.r53_resolver_name}-R53-Outbound-Resolver-${var.r53_resolver_random_string}"
  }
}

module "vpc_inbound_resolver_security_group" {
  count       = var.r53_create_inbound_resolver ? 1 : 0
  source      = "../vpc-security-group-ingress"
  name        = "${var.r53_resolver_name}-R53-Inbound-Resolver-Security-Group-${var.r53_resolver_random_string}"
  description = "${var.r53_resolver_name} R53 Inbound Resolver Security Group"
  vpc_id      = var.r53_resolver_vpc_id
  ports       = local.r53_inbound_ports
}

resource "aws_route53_resolver_endpoint" "r53_inbound_resolver" {
  count              = var.r53_create_inbound_resolver ? 1 : 0
  name               = "${var.r53_resolver_name}-R53-Inbound-Resolver-${var.r53_resolver_random_string}"
  direction          = "INBOUND"
  security_group_ids = [module.vpc_inbound_resolver_security_group[0].sg_id]
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[0]
  }
  ip_address {
    subnet_id = var.r53_resolver_subnet_ids[1]
  }
  tags = {
    Name = "${var.r53_resolver_name}-R53-Inbound-Resolver-${var.r53_resolver_random_string}"
  }
}
