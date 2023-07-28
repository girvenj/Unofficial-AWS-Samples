variable "ssm_association_approve_after_days" {
  description = "The number of days after the release date of each patch matched by the rule the patch is marked as approved in the patch baseline. Valid Range: 0 to 100."
  type        = number
}

variable "ssm_association_driver_deployment_rate" {
  description = "A rate expression that specifies when the driver check/update association runs."
  type        = string
}

variable "ssm_association_inventory_rate" {
  description = "A rate expression that specifies when the inventory association runs."
  type        = string
}

variable "ssm_association_launch_agent_deployment_rate" {
  description = "A rate expression that specifies when the Launch Agent check/update association runs."
  type        = string
}

variable "ssm_association_patching_deployment_rate" {
  description = "A rate expression that specifies when the patching check/update association runs."
  type        = string
}

variable "ssm_association_ssm_agent_deployment_rate" {
  description = "A rate expression that specifies when the SSM agent check/update association runs."
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

variable "ssm_association_patch_group_tag" {
  description = "Tag value for maintenance window and association application."
  type        = string
}

variable "ssm_association_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}
