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

variable "mad_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "mad_secret_kms_key" {
  default     = "aws/secretsmanager"
  description = "Alias for the KMS encryption key used to encrypt the admin crednetials"
  type        = string
}

variable "mad_subnet_ids" {
  description = "Private subnet IDs the AWS Managed Microsoft AD will be deployed to"
  type        = list(string)
}

variable "mad_vpc_id" {
  description = "VPC ID the AWS Managed Microsoft AD will be deployed to"
  type        = string
}
