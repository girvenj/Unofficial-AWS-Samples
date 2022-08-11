variable "r53_rule_domain_name" {
  description = "DNS queries for this domain name are forwarded to the IP addresses that are specified using target_ip"
  type        = string
}

variable "r53_rule_name" {
  description = "A friendly name that lets you easily find a rule in the Resolver dashboard in the Route 53 console"
  type        = string
}

variable "r53_rule_r53_outbound_resolver_id" {
  description = "The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses that you specify using target_ip"
  type        = string
}

variable "r53_rule_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "r53_rule_target_ip" {
  description = "Configuration block(s) indicating the IPs that you want Resolver to forward DNS queries to"
  type        = list(string)
}

variable "r53_rule_vpc_id" {
  description = "The ID of the VPC that you want to associate the resolver rule with"
  type        = string
}