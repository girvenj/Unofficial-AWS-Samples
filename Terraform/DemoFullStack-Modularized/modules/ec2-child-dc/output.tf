output "child_onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_child_dc.outputs.ChildOnpremDomainControllerInstanceID
}

output "child_onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_child_dc.outputs.ChildOnpremDomainControllerInstancePrivateIP
}
