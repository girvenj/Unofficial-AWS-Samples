variable "rds_allocated_storage" {
  description = "The allocated storage in gibibytes."
  type        = number
}

variable "rds_directory_id" {
  description = "AWS Managed Microsoft AD directory ID."
  type        = string
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

variable "rds_port_number" {
  description = "RDS SQL Intance integrated with AWS Managed Microsoft AD port number."
  type        = number
}

variable "rds_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}

variable "rds_storage_type" {
  description = "One of standard (magnetic), gp2 & gp3 (general purpose SSD), or io1 (provisioned IOPS SSD)."
  type        = string
  validation {
    condition     = contains(["gp2", "gp3", "io1", "standard"], var.rds_storage_type)
    error_message = "The storage type. value must be gp2, gp3, io1, or standard."
  }
}

variable "rds_subnet_ids" {
  description = "Private subnet ID(s) for Amazon RDS."
  type        = list(string)
}

variable "rds_username" {
  description = "Username for the master DB user."
  type        = string
}

variable "rds_vpc_id" {
  description = "VPC ID the Amazon RDS Instance will be deployed to."
  type        = string
}
