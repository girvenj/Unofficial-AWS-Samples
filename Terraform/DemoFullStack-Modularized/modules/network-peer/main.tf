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

resource "aws_route" "main" {
  provider                  = aws.primary
  route_table_id            = var.vpc_default_route_table_id
  destination_cidr_block    = var.peer_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "main_secondary" {
  provider                  = aws.secondary
  route_table_id            = var.peer_vpc_default_route_table_id
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}
