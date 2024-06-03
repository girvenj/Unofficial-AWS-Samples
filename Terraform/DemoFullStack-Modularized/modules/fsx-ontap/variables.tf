variable "fsx_ontap_alias" {
  description = "DNS alias name that you want to associate with the Amazon FSx file system."
  type        = string
}

variable "fsx_ontap_automatic_backup_retention_days" {
  description = "The number of days to retain automatic backups. Minimum of 0 and maximum of 90."
  type        = number
}

variable "fsx_ontap_deployment_type" {
  description = "Specifies the file system deployment type, valid values are MULTI_AZ_1, SINGLE_AZ_1 and SINGLE_AZ_2."
  type        = string
  validation {
    condition     = contains(["MULTI_AZ_1", "SINGLE_AZ_1", "SINGLE_AZ_2"], var.fsx_ontap_deployment_type)
    error_message = "The storage type value must be MULTI_AZ_1, SINGLE_AZ_1, or SINGLE_AZ_2"
  }
}

variable "fsx_ontap_dns_ips" {
  description = "A list of up to two IP addresses of DNS servers or domain controllers in the AD directory."
  type        = list(string)
}

variable "fsx_ontap_domain_fqdn" {
  description = "The fully qualified domain name of the AD directory, such as onpremises.local."
  type        = string
}

variable "fsx_ontap_domain_netbios_name" {
  description = "The short name of the directory, such as CORP."
  type        = string
}

variable "fsx_ontap_file_system_administrators_group" {
  description = "The name of the domain group whose members are granted administrative privileges for the file system."
  type        = string
}

variable "fsx_ontap_parent_ou_dn" {
  description = "The fully qualified distinguished name of the organizational unit within your AD directory that the Windows File Server instance will join, such as DC=onpremises,DC=local."
  type        = string
}

variable "fsx_ontap_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "fsx_ontap_root_volume_security_style" {
  description = "Specifies the root volume security style, Valid values are UNIX, NTFS, and MIXED."
  type        = string
  validation {
    condition     = contains(["UNIX", "NTFS", "MIXED"], var.fsx_ontap_root_volume_security_style)
    error_message = "The value must be UNIX, NTFS, or MIXED."
  }
}

variable "fsx_ontap_run_location" {
  description = "What type of Windows Server will the create FSx alias DNS record SSM Run Command run against, DomainController or MemberServer."
  type        = string
  validation {
    condition     = contains(["DomainController", "MemberServer"], var.fsx_ontap_run_location)
    error_message = "The value must be DomainController or MemberServer."
  }
}

variable "fsx_ontap_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536."
  type        = number
}

variable "fsx_ontap_storage_type" {
  description = "Specifies the storage type, valid values are SSD."
  type        = string
  validation {
    condition     = contains(["SSD"], var.fsx_ontap_storage_type)
    error_message = "The storage type value must be SSD."
  }
}

variable "fsx_ontap_subnet_ids" {
  description = "Private subnet ID(s) for the Amazon FSx for Windows File System."
  type        = list(string)
}

variable "fsx_ontap_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system. Minimum value of 8. Maximum value of 100000."
  type        = number
}

variable "fsx_ontap_username" {
  description = "The user name for the service account on your AD domain that Amazon FSx will use to join to your AD domain."
  type        = string
}

variable "fsx_ontap_vpc_id" {
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
