terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

resource "aws_directory_service_region" "example" {
  desired_number_of_domain_controllers = var.mad_new_region_desired_number_of_domain_controllers
  directory_id = var.mad_new_region_directory_id
  region_name  = var.mad_new_region_region_name
  vpc_settings {
    vpc_id     = var.mad_new_region_vpc_id
    subnet_ids = var.mad_new_region_subnet_ids
  }
  tags = {
    Name = "${var.mad_new_region_domain_fqdn}-MAD-${var.mad_new_region_random_string}"
  }
}

resource "aws_security_group_rule" "main" {
  type              = "egress"
  description       = "All outbound"
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  security_group_id = aws_directory_service_directory.main.security_group_id
}
