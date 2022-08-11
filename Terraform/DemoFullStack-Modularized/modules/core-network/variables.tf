variable "vpc_cidr" {
  description = "The IPv4 CIDR block for the VPC"
  type        = string
}

variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
}

variable "vpc_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}