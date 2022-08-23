variable "aws_region_primary" {
  description = "Primary AWS region"
  type        = string
}

variable "aws_region_secondary" {
  description = "Secondary AWS region"
  type        = string
}

variable "fsx_mad_alias" {
  description = "DNS alias name that you want to associate with the Amazon FSx file system"
  type        = string
}

variable "fsx_mad_automatic_backup_retention_days" {
  description = "The number of days to retain automatic backups. Minimum of 0 and maximum of 90"
  type        = number
}

variable "fsx_mad_deployment_type" {
  description = "Specifies the file system deployment type, valid values are MULTI_AZ_1, SINGLE_AZ_1 and SINGLE_AZ_2"
  type        = string
  validation {
    condition     = contains(["MULTI_AZ_1", "SINGLE_AZ_1", "SINGLE_AZ_2"], var.fsx_mad_deployment_type)
    error_message = "The storage type value must be MULTI_AZ_1, SINGLE_AZ_1, or SINGLE_AZ_2"
  }
}

variable "fsx_mad_kms_key" {
  description = "ARN for the KMS Key to encrypt the file system at rest"
  type        = string
}

variable "fsx_mad_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536"
  type        = number
}

variable "fsx_mad_storage_type" {
  description = "Specifies the storage type, valid values are SSD and HDD"
  type        = string
  validation {
    condition     = contains(["HDD", "SSD"], var.fsx_mad_storage_type)
    error_message = "The storage type value must be HDD or SSD."
  }
}

variable "fsx_mad_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system in power of 2 increments. Minimum of 8 and maximum of 2048"
  type        = number
}

variable "fsx_self_alias" {
  description = "DNS alias name that you want to associate with the Amazon FSx file system"
  type        = string
}

variable "fsx_self_automatic_backup_retention_days" {
  description = "The number of days to retain automatic backups. Minimum of 0 and maximum of 90"
  type        = number
}

variable "fsx_self_deployment_type" {
  description = "Specifies the file system deployment type, valid values are MULTI_AZ_1, SINGLE_AZ_1 and SINGLE_AZ_2"
  type        = string
  validation {
    condition     = contains(["MULTI_AZ_1", "SINGLE_AZ_1", "SINGLE_AZ_2"], var.fsx_self_deployment_type)
    error_message = "The storage type value must be MULTI_AZ_1, SINGLE_AZ_1, or SINGLE_AZ_2"
  }
}

variable "fsx_self_kms_key" {
  description = "ARN for the KMS Key to encrypt the file system at rest"
  type        = string
}

variable "fsx_self_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536"
  type        = number
}

variable "fsx_self_storage_type" {
  description = "Specifies the storage type, valid values are SSD and HDD"
  type        = string
  validation {
    condition     = contains(["HDD", "SSD"], var.fsx_self_storage_type)
    error_message = "The storage type value must be HDD or SSD."
  }
}

variable "fsx_self_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system in power of 2 increments. Minimum of 8 and maximum of 2048"
  type        = number
}

variable "mad_desired_number_of_domain_controllers" {
  description = "The number of domain controllers desired in the directory. Minimum value of 2"
  type        = number
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com"
  type        = string
}

variable "mad_domain_netbios" {
  description = "The NetBIOS name for the directory, such as CORP"
  type        = string
}

variable "mad_edition" {
  description = "The AWS Managed Microsoft AD edition"
  type        = string
  validation {
    condition     = contains(["Enterprise", "Standard"], var.mad_edition)
    error_message = "The edition value must be Enterprise or Standard."
  }
}

variable "mad_mgmt_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "mad_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the admin crednetials"
  type        = string
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD"
  type        = string
}

variable "onprem_additional_dc_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "onprem_child_dc_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
  type        = string
}

variable "onprem_child_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CHILD"
  type        = string
}

variable "onprem_pki_ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes"
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

variable "onprem_root_dc_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the Administrator credentials"
  type        = string
}

variable "r53_resolver_name" {
  description = "The friendly name of the Route 53 Resolver endpoint"
  type        = string
}

variable "rds_allocated_storage" {
  description = "The allocated storage in gibibytes"
  type        = number
}

variable "rds_engine" {
  description = "The database engine to use"
  type        = string
}

variable "rds_engine_version" {
  description = "The engine version to use. If auto_minor_version_upgrade is enabled, you can provide a prefix of the version such as 5.7 (for 5.7.10)"
  type        = string
}

variable "rds_identifier" {
  description = "The name of the RDS instance"
  type        = string
}

variable "rds_instance_class" {
  description = "The instance type of the RDS instance"
  type        = string
}

variable "rds_kms_key" {
  description = "Alias for the KMS encryption key"
  type        = string
}

variable "rds_port_number" {
  description = "RDS SQL Intance integrated with AWS Managed Microsoft AD port number"
  type        = number
}

variable "rds_secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the local db admin"
  type        = string
}

variable "rds_storage_type" {
  description = "One of standard (magnetic), gp2 (general purpose SSD), or io1 (provisioned IOPS SSD)"
  type        = string
  validation {
    condition     = contains(["gp2", "io1", "standard"], var.rds_storage_type)
    error_message = "The storage type. value must be gp2, io1, or standard."
  }
}

variable "rds_username" {
  description = "Username for the master DB user"
  type        = string
}

variable "vpc_cidr_primary" {
  description = "The IPv4 CIDR block for the VPC"
  type        = string
}

variable "vpc_name_primary" {
  description = "Name of the VPC"
  type        = string
}

variable "vpc_cidr_secondary" {
  description = "The IPv4 CIDR block for the VPC"
  type        = string
}

variable "vpc_name_secondary" {
  description = "Name of the VPC"
  type        = string
}
