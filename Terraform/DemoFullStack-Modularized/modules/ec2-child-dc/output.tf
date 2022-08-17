output "child_onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_child_dc.outputs.ChildOnpremDomainControllerInstanceID
}

output "child_onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_child_dc.outputs.ChildOnpremDomainControllerInstancePrivateIP
}

output "onprem_child_ad_domain_name" {
  value = join(".", ["${aws_cloudformation_stack.instance_child_dc.parameters.OnpremChildNetBiosName}", "${aws_cloudformation_stack.instance_child_dc.parameters.OnpremDomainName}"])
}

output "onprem_child_ad_netbios_name" {
  value = aws_cloudformation_stack.instance_child_dc.parameters.OnpremChildNetBiosName
}
