variable "kms_customer_master_key_spec" {
  description = "Specifies whether the key contains a symmetric key or an asymmetric key pair and the encryption algorithms or signing algorithms that the key supports. Valid values: SYMMETRIC_DEFAULT, RSA_2048, RSA_3072, RSA_4096, HMAC_256, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, or ECC_SECG_P256K1."
  type        = string
  validation {
    condition     = contains(["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096", "HMAC_256", "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1"], var.kms_customer_master_key_spec)
    error_message = "The key usage value must be SYMMETRIC_DEFAULT, RSA_2048, RSA_3072, RSA_4096, HMAC_256, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, or ECC_SECG_P256K1."
  }
}

variable "kms_enable_key_rotation" {
  description = "Specifies whether key rotation is enabled."
  type        = bool
}

variable "kms_key_alias_name" {
  description = "The display name of the alias."
  type        = string
}

variable "kms_key_deletion_window_in_days" {
  default     = 7
  description = "The waiting period, specified in number of days. After the waiting period ends, AWS KMS deletes the KMS key. The value must be between 7 and 30, inclusive."
  sensitive   = true
  type        = number
}

variable "kms_key_description" {
  default     = " "
  description = "The description of the key as viewed in AWS console."
  type        = string
}

variable "kms_key_usage" {
  description = "Specifies the intended use of the key. Valid values: ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC."
  type        = string
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"], var.kms_key_usage)
    error_message = "The key usage value must be ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC."
  }
}

variable "kms_random_string" {
  description = "Random string to ensure resource names are unique."
  type        = string
}
