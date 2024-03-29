variable "onprem_administrator_secret" {
  description = "Secret containing onpremises Administrator credentials."
  type        = string
}

variable "onprem_administrator_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Secrets."
  type        = string
}

variable "onprem_domain_fqdn" {
  description = "The fully qualified name for the domain, such as onpremises.local."
  type        = string
}

variable "onprem_domain_netbios" {
  description = "The NetBIOS name for the domain, such as ONPREMISES."
  type        = string
}

variable "onprem_pki_dns_resolver_ip" {
  description = "IP for DNS resolution of parent domain."
  type        = list(string)
}


variable "onprem_pki_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes."
  type        = string
}

variable "onprem_pki_ec2_ami_name" {
  description = "Name of the AMI that was provided during image creation."
  type        = string
}

variable "onprem_pki_ec2_ami_owner" {
  description = "List of AMI owners to limit search. Valid values: an AWS account ID, self (the current account), or an AWS owner alias (e.g., amazon, aws-marketplace, microsoft)."
  type        = string
}

variable "onprem_pki_ec2_instance_type" {
  description = "Instance type to use for the instance."
  type        = string
}

variable "onprem_pki_ec2_launch_template" {
  description = "Specifies a Launch Template to configure the instance. Parameters configured on this resource will override the corresponding parameters in the Launch Template."
  type        = string
}

variable "onprem_pki_patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "onprem_pki_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "onprem_pki_security_group_id" {
  description = "The ID of the security group to be attached the instance."
  type        = string
}

variable "onprem_pki_server_netbios_name" {
  description = "The NetBIOS name for the server, such as ONPREM-PKI01."
  type        = string
}

variable "onprem_pki_ssm_docs" {
  description = "SSM documents used to configure the instance."
  type        = list(string)
}

variable "onprem_pki_subnet_id" {
  description = "The ID of the subnet the instance will be deployed to."
  type        = string
}

variable "onprem_pki_vpc_cidr" {
  description = "VPC CIDR the instance will be deployed to."
  type        = string
}
