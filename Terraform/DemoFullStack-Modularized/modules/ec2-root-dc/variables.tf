variable "mad_admin_secret" {
  description = "Secret containing MAD Admin credentials"
  type        = string
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the AWS Managed Microsoft AD domain, such as corp.example.com"
  type        = string
}

variable "onprem_root_dc_deploy_fsx" {
  description = "Deploy FSx integrated with onpremises AD"
  type        = bool
}

variable "onprem_root_dc_domain_fqdn" {
  description = "The fully qualified name for the directory, such as onpremises.local"
  type        = string
}

variable "onprem_root_dc_domain_netbios" {
  description = "The fully qualified name for the domain, such as onpremises.local"
  type        = string
}

variable "onprem_root_dc_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "onprem_root_dc_fsx_ou" {
  description = "FSx integrated with onpremises AD parent OU"
  type        = string
}

variable "onprem_root_dc_fsx_administrators_group" {
  description = "The name of the domain group whose members are granted administrative privileges for the file system"
  type        = string
}

variable "onprem_root_dc_fsx_svc_username" {
  description = "The user name for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain"
  type        = string
}

variable "onprem_root_dc_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "onprem_root_dc_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Administrator credentials"
  type        = string
}

variable "onprem_root_dc_security_group_ids" {
  description = "The ID of the security group(s) to be attached the instance"
  type        = string
}

variable "onprem_root_dc_ssm_docs" {
  description = "SSM documents used to configure the instance"
  type        = list(string)
}

variable "onprem_root_dc_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to"
  type        = string
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD"
  type        = string
}

variable "onprem_root_dc_vpc_cidr" {
  description = "VPC CIDR instance will be deployed to"
  type        = string
}
