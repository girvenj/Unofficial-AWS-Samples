variable "onprem_administrator_secret" {
  description = "Secret containing onpremises Administrator credentials"
  type        = string
}

variable "onprem_dc_ip" {
  description = "IP of exisiting domain controller for DNS resolution of parent domain"
  type        = string
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the parent domain, such as onpremises.local"
  type        = string
}

variable "onprem_child_dc_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "onprem_child_dc_security_group_ids" {
  description = "The ID of the security group(s) to be attached the instance"
  type        = string
}

variable "onprem_child_dc_ssm_docs" {
  description = "SSM documents used to configure the instance"
  type        = list(string)
}

variable "onprem_child_dc_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to"
  type        = string
}

variable "onprem_child_dc_vpc_cidr" {
  description = "VPC CIDR the instance will be deployed to"
  type        = string
}

variable "onprem_child_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CHILD"
  type        = string
}
