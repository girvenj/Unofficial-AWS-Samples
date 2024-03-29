resource "aws_security_group" "r53_outbound_resolver_sg" {
  name        = "Demo-VPC-Outbound-Resolver-SG-${random_string.random_string.result}"
  description = "Demo-VPC-Outbound-Resolver-SG-${random_string.random_string.result}"

  dynamic "egress" {
    for_each = local.r53_ports
    iterator = r53_ports
    content {
      description = r53_ports.value.description
      from_port   = r53_ports.value.from_port
      to_port     = r53_ports.value.to_port
      protocol    = r53_ports.value.protocol
      cidr_blocks = [r53_ports.value.cidr_blocks]
    }
  }

  tags = {
    Name = "Demo-VPC-Outbound-Resolver-SG-${random_string.random_string.result}"
  }
  vpc_id = aws_vpc.network.id
}

resource "aws_route53_resolver_endpoint" "r53_outbound_resolver" {
  name               = "Demo-VPC-Outbound-Resolver-${random_string.random_string.result}"
  direction          = "OUTBOUND"
  security_group_ids = [aws_security_group.r53_outbound_resolver_sg.id]
  ip_address {
    subnet_id = aws_subnet.network_subnet1.id
  }
  ip_address {
    subnet_id = aws_subnet.network_subnet2.id
  }
  tags = {
    Name = "Demo-VPC-Outbound-Resolver-${random_string.random_string.result}"
  }
}

resource "aws_route53_resolver_rule" "r53_outbound_resolver_rule_mad" {
  domain_name          = var.mad_domain_fqdn
  name                 = "${var.mad_domain_netbios}-${random_string.random_string.result}"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.r53_outbound_resolver.id
  tags = {
    Name = "Demo-VPC-Outbound-Resolver-Rule-MAD-${random_string.random_string.result}"
  }
  target_ip {
    ip = tolist(aws_directory_service_directory.mad.dns_ip_addresses)[0]
  }
  target_ip {
    ip = tolist(aws_directory_service_directory.mad.dns_ip_addresses)[1]
  }
}

resource "aws_route53_resolver_rule_association" "r53_outbound_resolver_rule_mad_association" {
  name             = "Demo-VPC-Outbound-Resolver-Rule-Assoc-MAD-${random_string.random_string.result}"
  resolver_rule_id = aws_route53_resolver_rule.r53_outbound_resolver_rule_mad.id
  vpc_id           = aws_vpc.network.id
}

resource "aws_route53_resolver_rule" "r53_outbound_resolver_rule_onprem" {
  domain_name          = var.onprem_domain_fqdn
  name                 = "${var.onprem_domain_netbios}-${random_string.random_string.result}"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.r53_outbound_resolver.id
  tags = {
    Name = "Demo-VPC-Outbound-Resolver-Rule-Onprem-${random_string.random_string.result}"
  }
  target_ip {
    ip = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
  }
}

resource "aws_route53_resolver_rule_association" "r53_outbound_resolver_rule_onprem_association" {
  name             = "Demo-VPC-Outbound-Resolver-Rule-Assoc-Onprem-${random_string.random_string.result}"
  resolver_rule_id = aws_route53_resolver_rule.r53_outbound_resolver_rule_onprem.id
  vpc_id           = aws_vpc.network.id
}

resource "aws_route53_resolver_rule" "r53_outbound_resolver_rule_onprem_child" {
  count                = var.onprem_create_child_domain ? 1 : 0
  domain_name          = "${var.onprem_child_domain_netbios}.${var.onprem_domain_fqdn}"
  name                 = "${var.onprem_child_domain_netbios}-${random_string.random_string.result}"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.r53_outbound_resolver.id
  tags = {
    Name = "Demo-VPC-Outbound-Resolver-Rule-Onprem-Child-${random_string.random_string.result}"
  }
  target_ip {
    ip = aws_cloudformation_stack.instance_child_dc[0].outputs.ChildOnpremDomainControllerInstancePrivateIP
  }
}

resource "aws_route53_resolver_rule_association" "r53_outbound_resolver_rule_onprem_child_association" {
  count            = var.onprem_create_child_domain ? 1 : 0
  name             = "Demo-VPC-Outbound-Resolver-Rule-Assoc-Onprem_Child-${random_string.random_string.result}"
  resolver_rule_id = aws_route53_resolver_rule.r53_outbound_resolver_rule_onprem_child[0].id
  vpc_id           = aws_vpc.network.id
}
