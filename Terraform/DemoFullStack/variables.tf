variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "mad_deploy_fsx" {
  description = "Deploy FSx Integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_deploy_pki" {
  description = ""
  type        = bool
}

variable "mad_deploy_rds" {
  description = "Deploy RDS SQL Intance Integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com"
  type        = string
}

variable "mad_domain_netbios" {
  description = "The NetBIOS name for the directory, such as CORP"
  type        = string
}

variable "mad_edition" {
  description = "The AWS Managed Microsoft AD edition"
  type        = string
  validation {
    condition     = contains(["Enterprise", "Standard"], var.mad_edition)
    error_message = "The edition value must be Enterprise or Standard."
  }
}

variable "mad_onprem_trust_direction" {
  description = ""
  type        = string
  validation {
    condition     = contains(["One-Way: Incoming", "One-Way: Outgoing", "Two-Way"], var.mad_onprem_trust_direction)
    error_message = "The value must be Yes or No."
  }
}

variable "mad_user_admin" {
  description = "Name of the Admin account provision with AWS Managed Microsoft AD to be stored in a Secret with a random password"
  type        = string
}

/*variable "domain_password" {
  default     = "MyStrongPassword@"
  description = "The password for the Admin account provision with AWS Managed Microsoft AD"
  sensitive   = true
  type        = string
  ## Terraform - Sensitive Variables = https://learn.hashicorp.com/tutorials/terraform/sensitive-variables
}*/

variable "onprem_child_domain_netbios" {
  description = "The fully qualified name for the directory, such as ONPREMISES"
  type        = string
}

variable "onprem_create_child_domain" {
  description = ""
  type        = bool
}


variable "onprem_deploy_fsx" {
  description = ""
  type        = bool
}

variable "onprem_deploy_pki" {
  description = ""
  type        = bool
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the directory, such as onpremises.local"
  type        = string
}

variable "onprem_domain_netbios" {
  description = "The fully qualified name for the directory, such as ONPREMISES"
  type        = string
}

variable "onprem_fsx_ou" {
  description = ""
  type        = string
}

variable "onprem_user_admin" {
  description = "Name of the Administrator account provision with Microsoft AD to be stored in a Secret with a random password"
  type        = string
}

variable "rds_port_number" {
  description = ""
  type        = number
}

variable "vpc_cidr" {
  description = "VPC CIDR Block"
  type        = string
}

variable "ad_ports" {
  type = set(object({
    from_port   = number
    to_port     = number
    description = string
    protocol    = string
    cidr_blocks = string
  }))
}

variable "ms_ports" {
  type = set(object({
    from_port   = number
    to_port     = number
    description = string
    protocol    = string
    cidr_blocks = string
  }))
}

variable "pki_ports" {
  type = set(object({
    from_port   = number
    to_port     = number
    description = string
    protocol    = string
    cidr_blocks = string
  }))
}

variable "fsx_ports" {
  type = set(object({
    from_port   = number
    to_port     = number
    description = string
    protocol    = string
    cidr_blocks = string
  }))
}
