output "additional_onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_additional_dc.outputs.additionalOnpremDomainControllerInstanceID
}

output "additional_onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_additional_dc.outputs.additionalOnpremDomainControllerInstancePrivateIP
}