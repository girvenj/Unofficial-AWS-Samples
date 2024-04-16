variable "rds_self_allocated_storage" {
  description = "The allocated storage in gibibytes."
  type        = number
}

variable "rds_self_engine" {
  description = "The database engine to use."
  type        = string
}

variable "rds_self_engine_version" {
  description = "The engine version to use. If auto_minor_version_upgrade is enabled, you can provide a prefix of the version such as 5.7 (for 5.7.10)."
  type        = string
}

variable "rds_self_identifier" {
  description = "The name of the RDS instance."
  type        = string
}

variable "rds_self_instance_class" {
  description = "The instance type of the RDS instance."
  type        = string
}

variable "rds_self_port_number" {
  description = "RDS SQL Intance integrated with AWS Managed Microsoft AD port number."
  type        = number
}

variable "rds_self_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "rds_self_storage_type" {
  description = "One of standard (magnetic), gp2 & gp3 (general purpose SSD), or io1 (provisioned IOPS SSD)."
  type        = string
  validation {
    condition     = contains(["gp2", "gp3", "io1", "standard"], var.rds_self_storage_type)
    error_message = "The storage type. value must be gp2, gp3, io1, or standard."
  }
}

variable "rds_self_subnet_ids" {
  description = "Private subnet ID(s) for Amazon RDS."
  type        = list(string)
}

variable "rds_self_username" {
  description = "Username for the master DB user."
  type        = string
}

variable "rds_self_vpc_id" {
  description = "VPC ID the Amazon RDS Instance will be deployed to."
  type        = string
}

variable "setup_ec2_iam_role" {
  description = "IAM role attached to SSM Target EC2 instance."
  type        = string
}

variable "setup_secret_arn" {
  description = "Secret ARN of Secret containing credentials to setup the FSx Filesystem."
  type        = string
}

variable "setup_secret_kms_key_arn" {
  description = "KMS Key ARN used to encrypt Secret containing credentials to setup the FSx Filesystem."
  type        = string
}

variable "setup_ssm_target_instance_id" {
  description = "SSM Target EC2 instance ID."
  type        = string
}

variable "rds_self_dns_ips" {
  description = "A list of up to two IP addresses of DNS servers or domain controllers in the self-managed AD directory."
  type        = list(string)
}

variable "rds_self_domain_netbios_name" {
  description = "The short name of the directory, such as CORP."
  type        = string
}

variable "rds_self_domain_fqdn" {
  description = "The fully qualified domain name of the self-managed AD directory, such as onpremises.local."
  type        = string
}

variable "rds_self_administrators_group" {
  description = "The name of the domain group whose members are granted administrative privileges for RDS."
  type        = string
}

variable "rds_self_parent_ou_dn" {
  description = "The fully qualified distinguished name of the organizational unit within your self-managed AD directory that the RDS instance will join, such as DC=onpremises,DC=local."
  type        = string
}

variable "rds_self_svc_account_username" {
  description = "The user name for the service account on your self-managed AD domain that Amazon RDS will use to join to your AD domain."
  type        = string
}
