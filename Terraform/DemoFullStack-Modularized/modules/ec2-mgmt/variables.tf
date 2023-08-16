variable "mad_mgmt_admin_secret" {
  description = "Secret containing MAD Admin credentials"
  type        = string
}

variable "mad_mgmt_admin_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Secrets."
  type        = string
}

variable "mad_mgmt_deploy_pki" {
  description = "Deploy PKI integrated with AWS Managed Microsoft AD"
  type        = bool
}

variable "mad_mgmt_domain_fqdn" {
  description = "The fully qualified name for the domain, such as corp.example.com."
  type        = string
}

variable "mad_mgmt_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CORP."
  type        = string
}

variable "mad_mgmt_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "mad_mgmt_ec2_ami_name" {
  description = "Name of the AMI that was provided during image creation."
  type        = string
}

variable "mad_mgmt_ec2_ami_owner" {
  description = "List of AMI owners to limit search. Valid values: an AWS account ID, self (the current account), or an AWS owner alias (e.g., amazon, aws-marketplace, microsoft)."
  type        = string
}

variable "mad_mgmt_ec2_instance_type" {
  description = "Instance type to use for the instance."
  type        = string
}

variable "mad_mgmt_ec2_launch_template" {
  description = "Specifies a Launch Template to configure the instance. Parameters configured on this resource will override the corresponding parameters in the Launch Template."
  type        = string
}

variable "mad_mgmt_patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "mad_mgmt_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "mad_mgmt_security_group_id" {
  description = "The ID of the security group to be attached the instance."
  type        = string
}

variable "mad_mgmt_server_netbios_name" {
  description = "The NetBIOS name for the server, such as MAD-MGMT01."
  type        = string
}

variable "mad_mgmt_ssm_docs" {
  description = "SSM documents used to configure the instance."
  type        = list(string)
}

variable "mad_mgmt_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to."
  type        = string
}

variable "mad_mgmt_use_customer_managed_key" {
  description = "Create and use Customer Managed KMS Keys (CMK) for encryption"
  type        = bool
}

variable "mad_mgmt_vpc_cidr" {
  description = "VPC CIDDR the instance will be deployed to."
  type        = string
}
