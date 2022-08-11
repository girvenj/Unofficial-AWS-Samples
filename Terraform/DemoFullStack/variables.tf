variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "fsx_kms_key" {
  default     = "aws/fsx"
  description = "ARN for the KMS Key to encrypt the file system at rest"
  type        = string
}

variable "mad_deploy_fsx" {
  description = "Deploy FSx integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_deploy_pki" {
  description = "Deploy FSx integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_deploy_rds" {
  description = "Deploy RDS SQL instance integrated with AWS Managed Microsoft AD"
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
  description = "Trust between AWS Managed Microsoft AD and onpremises AD direction"
  type        = string
  validation {
    condition     = contains(["One-Way: Incoming", "One-Way: Outgoing", "Two-Way"], var.mad_onprem_trust_direction)
    error_message = "The value must be One-Way: Incoming, One-Way: Outgoing, or Two-Way"
  }
}

variable "onprem_child_domain_netbios" {
  description = "The fully qualified name for the directory, such as ONPREMISES"
  type        = string
}

variable "onprem_create_child_domain" {
  description = "Deploy child of onpremises AD"
  type        = bool
}

variable "onprem_deploy_fsx" {
  description = "Deploy FSx integrated with onpremises AD"
  type        = bool
}

variable "onprem_deploy_pki" {
  description = "Deploy PKI integrated with onpremises AD"
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
  description = "FSx integrated with onpremises AD parent OU"
  type        = string
}

variable "rds_kms_key" {
  default     = "aws/rds"
  description = "ARN for the KMS Key to encrypt the RDS instance"
  type        = string
}

variable "rds_port_number" {
  description = "RDS SQL Intance integrated with AWS Managed Microsoft AD port number"
  type        = number
}

variable "secret_kms_key" {
  default     = "aws/secretsmanager"
  description = "ARN or Id of the AWS KMS key to be used to encrypt the secret values in the versions stored in this secret"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}
