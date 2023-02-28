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

resource "aws_subnet" "public_subnet1" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 0)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Public-01-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public_subnet2" {
  availability_zone       = data.aws_availability_zones.available.names[1]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 1)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Public-02-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public_subnet3" {
  availability_zone       = data.aws_availability_zones.available.names[2]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 2)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Public-03-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "nat_subnet1" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 3)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-01-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "nat_subnet2" {
  availability_zone       = data.aws_availability_zones.available.names[1]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 4)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-02-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "nat_subnet3" {
  availability_zone       = data.aws_availability_zones.available.names[2]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 3, 5)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-03-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "private_subnet1" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, 12)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Private-01-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "private_subnet2" {
  availability_zone       = data.aws_availability_zones.available.names[1]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, 13)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Private-02-${var.vpc_random_string}"
  }
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "private_subnet3" {
  availability_zone       = data.aws_availability_zones.available.names[2]
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, 14)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-Private-03-${var.vpc_random_string}"
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
  route = []
  tags = {
    Name = "${var.vpc_name}-VPC-Default-RT-${var.vpc_random_string}"
  }
}

resource "aws_eip" "nat1" {
  vpc = true
}

resource "aws_eip" "nat2" {
  vpc = true
}

resource "aws_eip" "nat3" {
  vpc = true
}

resource "aws_nat_gateway" "nat1" {
  allocation_id     = aws_eip.nat1.id
  connectivity_type = "public"
  subnet_id         = aws_subnet.public_subnet1.id
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-01-${var.vpc_random_string}"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_ec2_tag" "nat1" {
  resource_id = aws_nat_gateway.nat1.network_interface_id
  key         = "Name"
  value       = "${var.vpc_name}-VPC-Subnet-NAT-01-${var.vpc_random_string}"
}

resource "aws_nat_gateway" "nat2" {
  allocation_id     = aws_eip.nat2.id
  connectivity_type = "public"
  subnet_id         = aws_subnet.public_subnet2.id
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-02-${var.vpc_random_string}"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_ec2_tag" "nat2" {
  resource_id = aws_nat_gateway.nat2.network_interface_id
  key         = "Name"
  value       = "${var.vpc_name}-VPC-Subnet-NAT-02-${var.vpc_random_string}"
}

resource "aws_nat_gateway" "nat3" {
  allocation_id     = aws_eip.nat3.id
  connectivity_type = "public"
  subnet_id         = aws_subnet.public_subnet3.id
  tags = {
    Name = "${var.vpc_name}-VPC-Subnet-NAT-03-${var.vpc_random_string}"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_ec2_tag" "nat3" {
  resource_id = aws_nat_gateway.nat3.network_interface_id
  key         = "Name"
  value       = "${var.vpc_name}-VPC-Subnet-NAT-03-${var.vpc_random_string}"
}

resource "aws_route_table" "nat1" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat1.id
  }
  tags = {
    Name = "${var.vpc_name}-VPC-RT-NAT-01-${var.vpc_random_string}"
  }
}

resource "aws_route_table" "nat2" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat2.id
  }
  tags = {
    Name = "${var.vpc_name}-VPC-RT-NAT-02-${var.vpc_random_string}"
  }
}

resource "aws_route_table" "nat3" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat3.id
  }
  tags = {
    Name = "${var.vpc_name}-VPC-RT-NAT-03-${var.vpc_random_string}"
  }
}

resource "aws_route_table_association" "nat_subnet1" {
  subnet_id      = aws_subnet.nat_subnet1.id
  route_table_id = aws_route_table.nat1.id
}

resource "aws_route_table_association" "nat_subnet2" {
  subnet_id      = aws_subnet.nat_subnet2.id
  route_table_id = aws_route_table.nat2.id
}

resource "aws_route_table_association" "nat_subnet3" {
  subnet_id      = aws_subnet.nat_subnet3.id
  route_table_id = aws_route_table.nat3.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route  = []
  tags = {
    Name = "${var.vpc_name}-VPC-RT-Private-${var.vpc_random_string}"
  }
}

resource "aws_route_table_association" "private_subnet1" {
  subnet_id      = aws_subnet.private_subnet1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_subnet2" {
  subnet_id      = aws_subnet.private_subnet2.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_subnet3" {
  subnet_id      = aws_subnet.private_subnet3.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = {
    Name = "${var.vpc_name}-VPC-RT-Public-${var.vpc_random_string}"
  }
}

resource "aws_route_table_association" "public_subnet1" {
  subnet_id      = aws_subnet.public_subnet1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_subnet2" {
  subnet_id      = aws_subnet.public_subnet2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_subnet3" {
  subnet_id      = aws_subnet.public_subnet3.id
  route_table_id = aws_route_table.public.id
}
