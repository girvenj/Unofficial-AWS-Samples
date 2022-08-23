variable "mad_new_region_desired_number_of_domain_controllers" {
  description = "The number of domain controllers desired in the directory. Minimum value of 2"
  type        = number
}

variable "mad_new_region_directory_id" {
  description = "The identifier of the directory to which you want to add Region replicationm"
  type        = string
}

variable "mad_new_region_domain_fqdn" {
  description = "The fully qualified name for the directory, such as corp.example.com"
  type        = string
}

variable "mad_new_region_random_string" {
  description = "Random string to ensure resource names are unique"
  type        = string
}

variable "mad_new_region_region_name" {
  description = "The name of the Region where you want to add domain controllers for replication."
  type        = string
}

variable "mad_new_region_subnet_ids" {
  description = "Private subnet IDs the AWS Managed Microsoft AD will be deployed to"
  type        = list(string)
}

variable "mad_new_region_vpc_id" {
  description = "VPC ID the AWS Managed Microsoft AD will be deployed to"
  type        = string
}
