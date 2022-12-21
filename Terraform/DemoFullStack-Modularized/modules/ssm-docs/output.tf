output "ssm_baseline_doc_name" {
  value = aws_ssm_document.ssm_baseline.name
}

output "ssm_auditpol_doc_name" {
  value = aws_ssm_document.ssm_auditpol.name
}

output "ssm_pki_doc_name" {
  value = aws_ssm_document.ssm_pki.name
}

output "ssm_fsx_alias_doc_name" {
  value = aws_ssm_document.ssm_fsx_alias.name
}