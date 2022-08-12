output "onprem_pki_instance_id" {
  value = aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstanceID
}

output "onprem_pki_ip" {
  value = aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstancePrivateIP
}
