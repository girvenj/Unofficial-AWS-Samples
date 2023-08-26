output "kms_alias_arn" {
  value = aws_kms_alias.main.arn
}

output "kms_alias_name" {
  value = aws_kms_alias.main.name
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "kms_key_id" {
  value = aws_kms_key.main.key_id
}
