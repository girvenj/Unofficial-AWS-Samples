terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"
  tags = {
    Name = "${var.vpc_name}-VPC-${var.vpc_random_string}"
  }
}

resource "aws_subnet" "main_subnet1" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 2, 0)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet1-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "main_subnet2" {
  availability_zone       = data.aws_availability_zones.available.names[1]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 2, 1)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet2-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.vpc_name}-VPC-IGW-${var.vpc_random_string}"
  }
}

resource "aws_default_route_table" "main" {
  default_route_table_id = aws_vpc.main.default_route_table_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = {
    Name = "${var.vpc_name}-VPC-Default-RT-${var.vpc_random_string}"
  }
}