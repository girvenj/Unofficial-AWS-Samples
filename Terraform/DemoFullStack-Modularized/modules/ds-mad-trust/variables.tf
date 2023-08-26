variable "mad_trust_directory_id" {
  description = ""
  type        = string
}

variable "mad_trust_mad_domain_dns_name" {
  description = "The fully qualified name for the directory, such as corp.example.com."
  type        = string
}

variable "mad_trust_mad_domain_resolver" {
  description = ""
  type        = list(string)
}

variable "mad_trust_onpremises_domain_dns_name" {
  description = "The fully qualified name for the directory, such as onpremises.local."
  type        = string
}

variable "mad_trust_onpremises_domain_netbios_name" {
  description = "The NetBIOS name for the directory, such as ONPREMISES."
  type        = string
}
variable "mad_trust_onpremises_domain_resolver" {
  description = ""
  type        = list(string)
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD."
  type        = string
  validation {
    condition     = contains(["Two-Way", "One-Way: Incoming", "One-Way: Outgoing"], var.mad_trust_direction)
    error_message = "The value must be Two-Way, One-Way: Incoming, or One-Way: Outgoing."
  }
}

variable "mad_trust_secret_arn" {
  description = ""
  type        = string
}

variable "mad_trust_secret_kms_key_arn" {
  description = ""
  type        = string
}

variable "mad_trust_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "mad_trust_onpremises_administrator_secret_arn" {
  description = ""
  type        = string
}

variable "mad_trust_onpremises_administrator_secret_kms_key_arn" {
  description = ""
  type        = string
}

variable "mad_trust_ssm_target_iam_role" {
  description = ""
  type        = string
}

variable "mad_trust_ssm_target_instance_id" {
  description = ""
  type        = string
}
