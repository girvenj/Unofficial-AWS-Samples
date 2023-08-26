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

variable "cad_parent_ou_dn" {
  description = "The fully qualified distinguished name of the organizational unit within your AD directory containing the AD Connector se, such as DC=onpremises,DC=local."
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

variable "cad_svc_username" {
  description = "The username of the AD Connector Service account."
  type        = string
}

variable "cad_vpc_id" {
  description = "The ARN of the VPC that the directory is in."
  type        = string
}

variable "setup_ec2_iam_role" {
  description = "IAM role attached to SSM Target EC2 instance."
  type        = string
}

variable "setup_secret_arn" {
  description = "Secret ARN of Secret containing credentials to setup the AD Connector."
  type        = string
}

variable "setup_secret_kms_key_arn" {
  description = "KMS Key ARN used to encrypt Secret containing credentials to setup the FSx Filesystem."
  type        = string
}

variable "setup_ssm_target_instance_id" {
  description = "SSM Target EC2 instance ID."
  type        = string
}