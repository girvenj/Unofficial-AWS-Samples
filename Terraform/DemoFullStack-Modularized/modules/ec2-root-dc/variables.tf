variable "mad_admin_secret" {
  description = "Secret containing MAD Admin credentials"
  type        = string
}

variable "mad_directory_id" {
  description = "Directory ID of the AWS Managed Microsoft AD domain."
  type        = string
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the AWS Managed Microsoft AD domain, such as corp.example.com"
  type        = string
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD."
  type        = string
  validation {
    condition     = contains(["None", "Two-Way", "One-Way: Incoming", "One-Way: Outgoing"], var.mad_trust_direction)
    error_message = "The edition value must be None, Two-Way, One-Way: Incoming, or One-Way: Outgoing."
  }
}

variable "onprem_root_dc_adc_svc_username" {
  default = "Connector_Svc"
  description = "The user name for the service account on your self-managed AD domain for AD Connector."
  type        = string
}

variable "onprem_root_dc_deploy_adc" {
  description = "Deploy AD Connector integrated with onpremises AD."
  type        = bool
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
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes."
  type        = string
}

variable "onprem_root_dc_ec2_ami_name" {
  description = "Name of the AMI that was provided during image creation."
  type        = string
}

variable "onprem_root_dc_ec2_ami_owner" {
  description = "List of AMI owners to limit search. Valid values: an AWS account ID, self (the current account), or an AWS owner alias (e.g., amazon, aws-marketplace, microsoft)."
  type        = string
}

variable "onprem_root_dc_ec2_instance_type" {
  description = "Instance type to use for the instance."
  type        = string
}

variable "onprem_root_dc_ec2_launch_template" {
  description = "Specifies a Launch Template to configure the instance. Parameters configured on this resource will override the corresponding parameters in the Launch Template."
  type        = string
}

variable "onprem_root_dc_fsx_svc_username" {
  default = "FSx_Svc"
  description = "The user name for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain."
  type        = string
}

variable "onprem_root_dc_patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "onprem_root_dc_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "onprem_root_dc_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Secrets."
  type        = string
}

variable "onprem_root_dc_security_group_id" {
  description = "The ID of the security group to be attached the instance."
  type        = string
}

variable "onprem_root_dc_server_netbios_name" {
  description = "The NetBIOS name for the server, such as ONPREM-DC01."
  type        = string
}

variable "onprem_root_dc_ssm_docs" {
  description = "SSM documents used to configure the instance."
  type        = list(string)
}

variable "onprem_root_dc_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to."
  type        = string
}

variable "onprem_root_dc_use_customer_managed_key" {
  description = "Create and use Customer Managed KMS Keys (CMK) for encryption"
  type        = bool
}

variable "onprem_root_dc_vpc_cidr" {
  description = "VPC CIDR instance will be deployed to."
  type        = string
}
