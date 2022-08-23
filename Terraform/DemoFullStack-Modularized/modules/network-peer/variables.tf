variable "peer_region" {
  description = "The region of the accepter VPC of the VPC Peering Connection"
  type        = string
}

variable "peer_vpc_cidr" {
  description = "The IPv4 CIDR of the accepter VPC"
  type        = string
}

variable "peer_vpc_default_route_table_id" {
  description = "The default route table id of the accepter VPC"
  type        = string
}

variable "peer_vpc_id" {
  description = "The ID of the accepter VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "The IPv4 CIDR of the requester VPC"
  type        = string
}

variable "vpc_default_route_table_id" {
  description = "The default route table id of the requester VPC"
  type        = string
}

variable "vpc_id" {
  description = "The ID of the requester VPC"
  type        = string
}
