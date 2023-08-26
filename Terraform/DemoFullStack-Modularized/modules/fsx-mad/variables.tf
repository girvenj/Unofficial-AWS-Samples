variable "fsx_mad_alias" {
  description = "DNS alias name that you want to associate with the Amazon FSx file system."
  type        = string
}

variable "fsx_mad_automatic_backup_retention_days" {
  description = "The number of days to retain automatic backups. Minimum of 0 and maximum of 90."
  type        = number
}

variable "fsx_mad_deployment_type" {
  description = "Specifies the file system deployment type, valid values are MULTI_AZ_1, SINGLE_AZ_1 and SINGLE_AZ_2."
  type        = string
  validation {
    condition     = contains(["MULTI_AZ_1", "SINGLE_AZ_1", "SINGLE_AZ_2"], var.fsx_mad_deployment_type)
    error_message = "The storage type value must be MULTI_AZ_1, SINGLE_AZ_1, or SINGLE_AZ_2."
  }
}

variable "fsx_mad_directory_id" {
  description = "AWS Managed Microsoft AD directory ID."
  type        = string
}

variable "fsx_mad_directory_netbios_name" {
  description = "The NetBIOS name for the directory, such as CORP."
  type        = string
}

variable "fsx_mad_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "fsx_mad_setup_secret_arn" {
  description = "Secret ARN of Secret containing credentials to setup the FSx Filesystem."
  type        = string
}

variable "fsx_mad_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536."
  type        = number
}

variable "fsx_mad_storage_type" {
  description = "Specifies the storage type, valid values are SSD and HDD."
  type = string
  validation {
    condition     = contains(["HDD", "SSD"], var.fsx_mad_storage_type)
    error_message = "The storage type value must be HDD or SSD."
  }
}

variable "fsx_mad_subnet_ids" {
  description = "Private subnet ID(s) for the Amazon FSx for Windows File System."
  type        = list(string)
}

variable "fsx_mad_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system in power of 2 increments. Minimum of 8 and maximum of 2048."
  type        = number
}

variable "fsx_mad_vpc_id" {
  description = "VPC ID the Amazon FSx for Windows File System will be deployed to."
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
