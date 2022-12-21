variable "r53_resolver_name" {
  description = "The friendly name of the Route 53 Resolver endpoint."
  type        = string
}

variable "r53_resolver_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "r53_resolver_subnet_ids" {
  description = "The ID of the subnets that you want to create the resolver endpoint in."
  type        = list(string)
}

variable "r53_resolver_vpc_id" {
  description = "The ID of the VPC that you want to create the resolver endpoint in."
  type        = string
}
