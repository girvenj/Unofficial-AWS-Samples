resource "aws_directory_service_directory" "mad" {
  edition    = var.mad_edition
  enable_sso = false
  name       = var.mad_domain_fqdn
  password   = random_password.secret_mad.result
  short_name = var.mad_domain_netbios
  tags = {
    Name = "${var.mad_domain_fqdn}-MAD-${random_string.random_string.result}"
  }
  type = "MicrosoftAD"
  vpc_settings {
    vpc_id     = aws_vpc.network.id
    subnet_ids = [aws_subnet.network_subnet1.id, aws_subnet.network_subnet2.id]
  }
}

resource "aws_security_group_rule" "mad" {
  type              = "egress"
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  security_group_id = aws_directory_service_directory.mad.security_group_id
}
