terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 4.0"
      configuration_aliases = [aws.primary, aws.secondary]
    }
  }
}

resource "aws_vpc_peering_connection" "main" {
  provider    = aws.primary
  peer_vpc_id = var.peer_vpc_id
  vpc_id      = var.vpc_id
  peer_region = var.peer_region
}

resource "aws_vpc_peering_connection_accepter" "main" {
  provider                  = aws.secondary
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
  auto_accept               = true
}

resource "aws_route" "nat1" {
  provider                  = aws.primary
  route_table_id            = var.vpc_nat1_rt
  destination_cidr_block    = var.peer_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "nat2" {
  provider                  = aws.primary
  route_table_id            = var.vpc_nat2_rt
  destination_cidr_block    = var.peer_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "nat3" {
  provider                  = aws.primary
  route_table_id            = var.vpc_nat3_rt
  destination_cidr_block    = var.peer_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "public" {
  provider                  = aws.primary
  route_table_id            = var.vpc_public_rt
  destination_cidr_block    = var.peer_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "peering_nat1" {
  provider                  = aws.secondary
  route_table_id            = var.peer_vpc_nat1_rt
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "peering_nat2" {
  provider                  = aws.secondary
  route_table_id            = var.peer_vpc_nat2_rt
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "peering_nat3" {
  provider                  = aws.secondary
  route_table_id            = var.peer_vpc_nat3_rt
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "peering_public" {
  provider                  = aws.secondary
  route_table_id            = var.peer_vpc_public_rt
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}
