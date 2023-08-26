output "onprem_ad_domain_name" {
  value = aws_cloudformation_stack.instance_root_dc.parameters.OnpremDomainName
}

output "onprem_ad_ebs_kms_key_alias_name" {
  value = module.kms_ebs_key.kms_alias_name
}

output "onprem_ad_ebs_kms_key_arn" {
  value = module.kms_ebs_key.kms_key_arn
}

output "onprem_ad_iam_role_name" {
  value = aws_iam_role.ec2.name 
}

output "onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
}

output "onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
}

output "onprem_ad_netbios_name" {
  value = aws_cloudformation_stack.instance_root_dc.parameters.OnpremNetBiosName
}

output "onprem_ad_password_secret_arn" {
  value = module.store_secret_administrator.secret_arn
}

output "onprem_ad_password_secret_id" {
  value = module.store_secret_administrator.secret_id
}

output "onprem_ad_password_secret_kms_key_arn" {
  value = module.kms_key.kms_key_arn
}
