variable "name" {
  description = "Security group name"
  type        = string
}

variable "description" {
  description = "Security group description"
  type        = string
}

variable "ports" {
  description = "List of maps containing security group rule information"
  type        = list(any)
}

variable "vpc_id" {
  description = "VPC ID where security group created in"
  type        = string
}
