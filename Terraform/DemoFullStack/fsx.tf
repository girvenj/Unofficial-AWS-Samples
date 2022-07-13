resource "aws_security_group" "fsx" {
  #count       = var.mad_deploy_fsx ? 1 : 0
  name        = "FSx-Security-Group-${random_string.random_string.result}"
  description = "FSx Security Group"

  dynamic "ingress" {
    for_each = var.fsx_ports
    iterator = fsx_ports
    content {
      description = fsx_ports.value.description
      from_port   = fsx_ports.value.from_port
      to_port     = fsx_ports.value.to_port
      protocol    = fsx_ports.value.protocol
      cidr_blocks = [fsx_ports.value.cidr_blocks]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "FSx-Security-Group-${random_string.random_string.result}"
  }
  vpc_id = aws_vpc.network.id
  depends_on = [
    aws_vpc.network
  ]
}

resource "aws_fsx_windows_file_system" "mad_fsx" {
  count                           = var.mad_deploy_fsx ? 1 : 0
  active_directory_id             = aws_directory_service_directory.mad.id
  aliases                         = ["MAD-FSx.${var.mad_domain_fqdn}"]
  automatic_backup_retention_days = 0
  storage_capacity                = 32
  throughput_capacity             = 16
  storage_type                    = "SSD"
  deployment_type                 = "SINGLE_AZ_2"
  subnet_ids                      = [aws_subnet.network_subnet1.id]
  preferred_subnet_id             = aws_subnet.network_subnet1.id
  security_group_ids              = [aws_security_group.fsx.id]
  skip_final_backup               = true
  tags = {
    Name = "MAD-FSx-${random_string.random_string.result}"
  }
  depends_on = [
    aws_directory_service_directory.mad,
    aws_security_group.fsx,
    aws_subnet.network_subnet1
  ]
}

resource "aws_fsx_windows_file_system" "onprem_fsx" {
  count                           = var.onprem_deploy_fsx ? 1 : 0
  aliases                         = ["Onprem-FSx.${var.onprem_domain_fqdn}"]
  automatic_backup_retention_days = 0
  storage_capacity                = 32
  throughput_capacity             = 16
  storage_type                    = "SSD"
  deployment_type                 = "SINGLE_AZ_2"
  subnet_ids                      = [aws_subnet.network_subnet1.id]
  preferred_subnet_id             = aws_subnet.network_subnet1.id
  security_group_ids              = [aws_security_group.fsx.id]
  skip_final_backup               = true
  tags = {
    Name = "Onprem-FSx-${random_string.random_string.result}"
  }
  self_managed_active_directory {
    dns_ips                                = [aws_cloudformation_stack.instances_rootdc.outputs.OnpremDomainControllerInstancePrivateIP]
    domain_name                            = var.onprem_domain_fqdn
    file_system_administrators_group       = "FSxAdmins"
    organizational_unit_distinguished_name = "OU=FSx,${var.onprem_fsx_ou}"
    password                               = random_password.secret_onprem.result
    username                               = "FSxServiceAccount"
  }
  depends_on = [
    aws_cloudformation_stack.instances_rootdc,
    aws_security_group.fsx,
    aws_subnet.network_subnet1
  ]
}
