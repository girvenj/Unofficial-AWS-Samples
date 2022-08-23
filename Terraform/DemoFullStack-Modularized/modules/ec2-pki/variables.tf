variable "onprem_administrator_secret" {
  description = "Secret containing onpremises Administrator credentials"
  type        = string
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the domain, such as onpremises.local"
  type        = string
}

variable "onprem_domain_netbios" {
  description = "The NetBIOS name for the domain, such as ONPREMISES"
  type        = string
}

variable "onprem_pki_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "onprem_pki_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "onprem_pki_security_group_ids" {
  description = "The ID of the security group(s) to be attached the instance"
  type        = string
}

variable "onprem_pki_ssm_docs" {
  description = "SSM documents used to configure the instance"
  type        = list(string)
}

variable "onprem_pki_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to"
  type        = string
}

variable "onprem_pki_vpc_cidr" {
  description = "VPC CIDR the instance will be deployed to"
  type        = string
}
