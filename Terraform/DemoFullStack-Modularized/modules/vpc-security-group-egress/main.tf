terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

resource "aws_security_group" "sg" {
  name        = var.name
  description = var.description
  vpc_id      = var.vpc_id

  dynamic "egress" {
    for_each = var.ports
    iterator = ports
    content {
      description = ports.value.description
      from_port   = ports.value.from_port
      to_port     = ports.value.to_port
      protocol    = ports.value.protocol
      cidr_blocks = [ports.value.cidr_blocks]
    }
  }
  tags = {
    Name = var.name
  }
}
