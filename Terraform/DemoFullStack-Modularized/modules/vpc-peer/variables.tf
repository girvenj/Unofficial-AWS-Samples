variable "peer_region" {
  description = "The region of the accepter VPC of the VPC Peering Connection."
  type        = string
}

variable "peer_vpc_cidr" {
  description = "The IPv4 CIDR of the accepter VPC."
  type        = string
}

variable "peer_vpc_nat1_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "peer_vpc_nat2_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "peer_vpc_nat3_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "peer_vpc_public_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "peer_vpc_id" {
  description = "The ID of the accepter VPC."
  type        = string
}

variable "vpc_cidr" {
  description = "The IPv4 CIDR of the requester VPC."
  type        = string
}

variable "vpc_nat1_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "vpc_nat2_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "vpc_nat3_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "vpc_public_rt" {
  description = "The route table id of the requester VPC."
  type        = string
}

variable "vpc_id" {
  description = "The ID of the requester VPC."
  type        = string
}
