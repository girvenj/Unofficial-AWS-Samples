output "managed_ad_mgmt_iam_role_name" {
  value = aws_iam_role.ec2.name 
}

output "managed_ad_mgmt_instance_id" {
  value = aws_cloudformation_stack.instance_mad_mgmt.outputs.MADMgmtInstanceID
}

output "managed_ad_mgmt_ip" {
  value = aws_cloudformation_stack.instance_mad_mgmt.outputs.MADMgmtInstancePrivateIP
}
