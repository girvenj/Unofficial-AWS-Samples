variable "description" {
  default     = " "
  description = "Description of the secret."
  type        = string
}

variable "name" {
  description = "Friendly name of the new secret. The secret name can consist of uppercase letters, lowercase letters, digits, and any of the following characters: /_+=.@-."
  type        = string
}

variable "password" {
  description = "Password of credential stored in Secret."
  sensitive   = true
  type        = string
}

variable "recovery_window_in_days" {
  default     = 0
  description = "Number of days that AWS Secrets Manager waits before it can delete the secret."
  sensitive   = true
  type        = number
}

variable "secret_kms_key" {
  default     = "aws/secretsmanager"
  description = "ARN or Id of the AWS KMS key to be used to encrypt the secret values in the versions stored in this secret."
  type        = string
}

variable "username" {
  description = "Username of credential stored in Secret."
  sensitive   = true
  type        = string
}
