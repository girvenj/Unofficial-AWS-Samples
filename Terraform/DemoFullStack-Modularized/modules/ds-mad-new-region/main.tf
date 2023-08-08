terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
      configuration_aliases = [aws.primary, aws.secondary]
    }
  }
}

resource "aws_directory_service_region" "main" {
  provider                             = aws.primary
  desired_number_of_domain_controllers = var.mad_new_region_desired_number_of_domain_controllers
  directory_id                         = var.mad_new_region_directory_id
  region_name                          = var.mad_new_region_region_name
  vpc_settings {
    vpc_id     = var.mad_new_region_vpc_id
    subnet_ids = var.mad_new_region_subnet_ids
  }
  tags = {
    Name = "${var.mad_new_region_domain_fqdn}-MAD-${var.mad_new_region_random_string}"
  }
}

data "aws_security_groups" "main" {
  provider = aws.secondary
  filter {
    name   = "group-name"
    values = ["${var.mad_new_region_directory_id}_controllers"]
  }
  filter {
    name   = "vpc-id"
    values = [var.mad_new_region_vpc_id]
  }
  depends_on = [
    aws_directory_service_region.main
  ]
}

resource "aws_security_group_rule" "main" {
  provider          = aws.secondary
  type              = "egress"
  description       = "All outbound"
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  security_group_id = data.aws_security_groups.main.ids[0]
}
