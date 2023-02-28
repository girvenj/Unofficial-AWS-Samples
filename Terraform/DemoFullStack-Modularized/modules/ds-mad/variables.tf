variable "mad_desired_number_of_domain_controllers" {
  description = "The number of domain controllers desired in the directory. Minimum value of 2."
  type        = number
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com."
  type        = string
}

variable "mad_domain_netbios" {
  description = "The NetBIOS name for the directory, such as CORP."
  type        = string
}

variable "mad_edition" {
  description = "The AWS Managed Microsoft AD edition."
  type        = string
  validation {
    condition     = contains(["Enterprise", "Standard"], var.mad_edition)
    error_message = "The edition value must be Enterprise or Standard."
  }
}

variable "mad_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "mad_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Secrets."
  type        = string
}

variable "mad_subnet_ids" {
  description = "Private subnet IDs the AWS Managed Microsoft AD will be deployed to."
  type        = list(string)
}

variable "mad_vpc_id" {
  description = "VPC ID the AWS Managed Microsoft AD will be deployed to."
  type        = string
}
