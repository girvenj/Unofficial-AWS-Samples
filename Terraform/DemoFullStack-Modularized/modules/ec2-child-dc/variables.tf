variable "onprem_administrator_secret" {
  description = "Secret containing onpremises Administrator credentials."
  type        = string
}

variable "onprem_administrator_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Secrets."
  type        = string
}

variable "onprem_child_dc_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes."
  type        = string
}

variable "onprem_child_dc_ec2_ami_name" {
  description = "Name of the AMI that was provided during image creation."
  type        = string
}

variable "onprem_child_dc_ec2_ami_owner" {
  description = "List of AMI owners to limit search. Valid values: an AWS account ID, self (the current account), or an AWS owner alias (e.g., amazon, aws-marketplace, microsoft)."
  type        = string
}

variable "onprem_child_dc_patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "onprem_child_dc_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "onprem_child_dc_security_group_id" {
  description = "The ID of the security group to be attached the instance."
  type        = string
}

variable "onprem_child_dc_ssm_docs" {
  description = "SSM documents used to configure the instance."
  type        = list(string)
}

variable "onprem_child_dc_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to."
  type        = string
}

variable "onprem_child_dc_use_customer_managed_key" {
  description = "Create and use Customer Managed KMS Keys (CMK) for encryption"
  type        = bool
}

variable "onprem_child_dc_vpc_cidr" {
  description = "VPC CIDR the instance will be deployed to."
  type        = string
}

variable "onprem_child_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CHILD."
  type        = string
}

variable "onprem_dc_ip" {
  description = "IP of exisiting domain controller for DNS resolution of parent domain."
  type        = string
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the parent domain, such as onpremises.local."
  type        = string
}
