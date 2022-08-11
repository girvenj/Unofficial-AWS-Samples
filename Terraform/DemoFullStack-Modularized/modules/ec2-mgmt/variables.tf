variable "mad_mgmt_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "mad_mgmt_admin_secret" {
  description = "Secret containing MAD Admin credentials"
  type        = string
}

variable "mad_mgmt_deploy_pki" {
  description = "Deploy PKI integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_mgmt_directory_id" {
  description = "Directory ID of the AWS Managed Microsoft AD domain"
  type        = string
}

variable "mad_mgmt_domain_fqdn" {
  description = "The fully qualified name for the domain, such as corp.example.com"
  type        = string
}

variable "mad_mgmt_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CORP"
  type        = string
}

variable "mad_mgmt_security_group_ids" {
  description = "The ID of the security group(s) to be attached the instance"
  type        = string
}

variable "mad_mgmt_ssm_docs" {
  description = "SSM documents used to configure the instance"
  type        = list(string)
}

variable "mad_mgmt_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to"
  type        = string
}

variable "mad_mgmt_vpc_cidr" {
  description = "VPC CIDDR the instance will be deployed to"
  type        = string
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD"
  type        = string
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the onpremises domain, such as onpremises.local"
  type        = string
}
