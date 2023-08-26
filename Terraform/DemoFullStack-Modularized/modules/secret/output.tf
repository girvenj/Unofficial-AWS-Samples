output "secret_arn" {
  value = aws_secretsmanager_secret.main.arn
}

output "secret_id" {
  value = aws_secretsmanager_secret.main.id
}
