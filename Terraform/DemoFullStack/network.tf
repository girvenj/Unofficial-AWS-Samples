data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_vpc" "network" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"
  tags = {
    Name = "Demo-VPC-${random_string.random_string.result}"
  }
}

resource "aws_subnet" "network_subnet1" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = cidrsubnet(aws_vpc.network.cidr_block, 2, 0)
  map_public_ip_on_launch = true
  tags = {
    Name = "Demo-VPC-Subnet1-${random_string.random_string.result}"
  }
  vpc_id = aws_vpc.network.id
  depends_on = [
    data.aws_availability_zones.available,
    aws_vpc.network
  ]
}

resource "aws_subnet" "network_subnet2" {
  availability_zone       = data.aws_availability_zones.available.names[1]
  cidr_block              = cidrsubnet(aws_vpc.network.cidr_block, 2, 1)
  map_public_ip_on_launch = true
  tags = {
    Name = "Demo-VPC-Subnet2-${random_string.random_string.result}"
  }
  vpc_id = aws_vpc.network.id
  depends_on = [
    data.aws_availability_zones.available,
    aws_vpc.network
  ]
}

resource "aws_internet_gateway" "network" {
  vpc_id = aws_vpc.network.id
  tags = {
    Name = "Demo-VPC-IGW-${random_string.random_string.result}"
  }
  depends_on = [
    aws_vpc.network
  ]
}

resource "aws_default_route_table" "network" {
  default_route_table_id = aws_vpc.network.default_route_table_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.network.id
  }
  tags = {
    Name = "Demo-VPC-Default-RT-${random_string.random_string.result}"
  }
  depends_on = [
    aws_internet_gateway.network,
    aws_vpc.network
  ]
}
