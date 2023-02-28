variable "cad_dns_ips" {
  description = "The DNS IP addresses of the domain to connect to.."
  type        = list(string)
}

variable "cad_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com."
  type        = string
}

variable "cad_domain_netbios_name" {
  description = "The short name of the directory, such as CORP."
  type        = string
}

variable "cad_password_secret" {
  description = "The password for the service account on your self-managed AD domain that AD COnnector will use."
  type        = string
}

variable "cad_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "cad_size" {
  description = "The size of the directory (Small or Large are accepted values). Large by default."
  type        = string
  validation {
    condition     = contains(["Small", "Large"], var.cad_size)
    error_message = "The size value must be Small or Large."
  }
}

variable "cad_subnet_ids" {
  description = "The identifiers of the subnets for the directory servers (2 subnets in 2 different AZs)."
  type        = list(string)
}

variable "cad_vpc_id" {
  description = "The identifier of the VPC that the directory is in."
  type        = string
}
