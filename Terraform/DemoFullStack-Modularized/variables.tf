variable "aws_region_primary" {
  description = "Primary AWS region."
  type        = string
}

variable "aws_region_secondary" {
  description = "Secondary AWS region."
  type        = string
}

variable "cad_size" {
  description = "The size of the directory (Small or Large are accepted values). Large by default."
  type        = string
  validation {
    condition     = contains(["Small", "Large"], var.cad_size)
    error_message = "The size value must be Small or Large."
  }
}

variable "default_ec2_instance_type" {
  description = "Instance type to use for the instances."
  type        = string
}

variable "ec2_ami_name" {
  description = "Name of the AMI that was provided during image creation."
  type        = string
}

variable "ec2_ami_owner" {
  description = "List of AMI owners to limit search. Valid values: an AWS account ID, self (the current account), or an AWS owner alias (e.g., amazon, aws-marketplace, microsoft)."
  type        = string
}

variable "ebs_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt the EBS volumes."
  type        = string
}

variable "fsx_kms_key" {
  description = "Alias for the KMS Key to encrypt the file system at rest."
  type        = string
}

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

variable "fsx_mad_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536."
  type        = number
}

variable "fsx_mad_storage_type" {
  description = "Specifies the storage type, valid values are SSD and HDD."
  type        = string
  validation {
    condition     = contains(["HDD", "SSD"], var.fsx_mad_storage_type)
    error_message = "The storage type value must be HDD or SSD."
  }
}

variable "fsx_mad_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system in power of 2 increments. Minimum of 8 and maximum of 2048."
  type        = number
}

variable "fsx_self_alias" {
  description = "DNS alias name that you want to associate with the Amazon FSx file system."
  type        = string
}

variable "fsx_self_automatic_backup_retention_days" {
  description = "The number of days to retain automatic backups. Minimum of 0 and maximum of 90."
  type        = number
}

variable "fsx_self_deployment_type" {
  description = "Specifies the file system deployment type, valid values are MULTI_AZ_1, SINGLE_AZ_1 and SINGLE_AZ_2."
  type        = string
  validation {
    condition     = contains(["MULTI_AZ_1", "SINGLE_AZ_1", "SINGLE_AZ_2"], var.fsx_self_deployment_type)
    error_message = "The storage type value must be MULTI_AZ_1, SINGLE_AZ_1, or SINGLE_AZ_2."
  }
}

variable "fsx_self_storage_capacity" {
  description = "Storage capacity (GiB) of the file system. Minimum of 32 and maximum of 65536."
  type        = number
}

variable "fsx_self_storage_type" {
  description = "Specifies the storage type, valid values are SSD and HDD."
  type        = string
  validation {
    condition     = contains(["HDD", "SSD"], var.fsx_self_storage_type)
    error_message = "The storage type value must be HDD or SSD."
  }
}

variable "fsx_self_throughput_capacity" {
  description = "Throughput (megabytes per second) of the file system in power of 2 increments. Minimum of 8 and maximum of 2048."
  type        = number
}

variable "mad_desired_number_of_domain_controllers" {
  description = "The number of domain controllers desired in the directory. Minimum value of 2."
  type        = number
}

variable "mad_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com."
  type        = string
}

variable "mad_domain_netbios" {
  description = "The NetBIOS name for the directory, such as CORP."
  type        = string
}

variable "mad_edition" {
  description = "The AWS Managed Microsoft AD edition."
  type        = string
  validation {
    condition     = contains(["Enterprise", "Standard"], var.mad_edition)
    error_message = "The edition value must be Enterprise or Standard."
  }
}

variable "mad_mgmt_server_netbios_name" {
  description = "The NetBIOS name for the server, such as MAD-MGMT01."
  type        = string
}

variable "mad_trust_direction" {
  description = "Direction of trust between MAD and onpremises AD."
  type        = string
  validation {
    condition     = contains(["None", "Two-Way", "One-Way: Incoming", "One-Way: Outgoing"], var.mad_trust_direction)
    error_message = "The value must be None, Two-Way, One-Way: Incoming, or One-Way: Outgoing."
  }
}

variable "onprem_child_dc_server_netbios_name" {
  description = "The NetBIOS name for the server, such as CHILD-DC01."
  type        = string
}

variable "onprem_child_domain_netbios" {
  description = "The NetBIOS name for the domain, such as CHILD."
  type        = string
}

variable "onprem_root_dc_adc_svc_username" {
  description = "The user name for the service account on your self-managed AD domain for AD Connector."
  type        = string
}

variable "onprem_root_additional_dc_server_netbios_name" {
  description = "The NetBIOS name for the server, such as Additional-DC01."
  type        = string
}

variable "onprem_root_dc_deploy_adc" {
  description = "Deploy AD Connector integrated with onpremises AD."
  type        = bool
}

variable "onprem_root_dc_deploy_fsx" {
  description = "Deploy FSx integrated with onpremises AD."
  type        = bool
}

variable "onprem_root_dc_domain_fqdn" {
  description = "The fully qualified name for the directory, such as onpremises.local."
  type        = string
}

variable "onprem_root_dc_domain_netbios" {
  description = "The fully qualified name for the domain, such as onpremises.local."
  type        = string
}

variable "onprem_root_dc_fsx_administrators_group" {
  description = "The name of the domain group whose members are granted administrative privileges for the file system."
  type        = string
}

variable "onprem_root_dc_fsx_ou" {
  description = "FSx integrated with onpremises AD parent OU."
  type        = string
}

variable "onprem_root_dc_fsx_svc_username" {
  description = "The user name for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain."
  type        = string
}

variable "onprem_root_dc_server_netbios_name" {
  description = "The NetBIOS name for the server, such as ONPREM-DC01."
  type        = string
}

variable "onprem_root_pki_server_netbios_name" {
  description = "The NetBIOS name for the server, such as ONPREM-PKI01."
  type        = string
}

variable "patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "r53_resolver_name" {
  description = "The friendly name of the Route 53 Resolver endpoint."
  type        = string
}

variable "rds_allocated_storage" {
  description = "The allocated storage in gibibytes."
  type        = number
}

variable "rds_engine" {
  description = "The database engine to use."
  type        = string
}

variable "rds_engine_version" {
  description = "The engine version to use. If auto_minor_version_upgrade is enabled, you can provide a prefix of the version such as 5.7 (for 5.7.10)."
  type        = string
}

variable "rds_identifier" {
  description = "The name of the RDS instance."
  type        = string
}

variable "rds_instance_class" {
  description = "The instance type of the RDS instance."
  type        = string
}

variable "rds_kms_key" {
  description = "Alias for the KMS encryption key."
  type        = string
}

variable "rds_port_number" {
  description = "RDS SQL Intance integrated with AWS Managed Microsoft AD port number."
  type        = number
}

variable "rds_storage_type" {
  description = "One of standard (magnetic), gp2 (general purpose SSD), or io1 (provisioned IOPS SSD)."
  type        = string
  validation {
    condition     = contains(["gp2", "io1", "standard"], var.rds_storage_type)
    error_message = "The storage type. value must be gp2, io1, or standard."
  }
}

variable "rds_username" {
  description = "Username for the master DB user."
  type        = string
}

variable "secret_kms_key" {
  description = "Alias for the KMS encryption key used to encrypt Secrets."
  type        = string
}

variable "ssm_association_approve_after_days" {
  description = "The number of days after the release date of each patch matched by the rule the patch is marked as approved in the patch baseline. Valid Range: 0 to 100."
  type        = number
}

variable "ssm_association_deployment_rate" {
  description = "A rate expression that specifies when the association runs."
  type        = string
}

variable "ssm_association_inventory_rate" {
  description = "A rate expression that specifies when the inventory association runs."
  type        = string
}

variable "ssm_association_max_concurrency" {
  description = "The maximum number of targets this task can be run for in parallel."
  type        = string
}

variable "ssm_association_max_errors" {
  description = "The maximum number of errors allowed before this task stops being scheduled."
  type        = string
}

variable "use_customer_managed_keys" {
  description = "Create and use Customer Managed KMS Keys (CMK) for encryption"
  type        = bool
}

variable "vpc_cidr_primary" {
  description = "The IPv4 CIDR block for the VPC."
  type        = string
}

variable "vpc_cidr_secondary" {
  description = "The IPv4 CIDR block for the VPC."
  type        = string
}

variable "vpc_name_primary" {
  description = "Name of the VPC."
  type        = string
}

variable "vpc_name_secondary" {
  description = "Name of the VPC."
  type        = string
}
