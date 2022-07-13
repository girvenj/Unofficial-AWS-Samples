aws_region                  = "us-east-2"
mad_deploy_fsx              = true
mad_deploy_pki              = true
mad_deploy_rds              = true
mad_domain_fqdn             = "corp.example.com"
mad_domain_netbios          = "CORP"
mad_edition                 = "Enterprise"
mad_onprem_trust_direction  = "Two-Way"
mad_user_admin              = "Admin"
onprem_child_domain_netbios = "CHILD"
onprem_create_child_domain  = true
onprem_deploy_fsx           = true
onprem_deploy_pki           = true
onprem_domain_fqdn          = "onpremises.local"
onprem_domain_netbios       = "ONPREMISES"
onprem_fsx_ou               = "DC=onpremises,DC=local"
onprem_user_admin           = "Administrator"
rds_port_number             = 1433
vpc_cidr                    = "10.0.0.0/24"

ad_ports = [
  {
    from_port   = 53
    to_port     = 53
    description = "DNS"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 53
    to_port     = 53
    description = "DNS"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 88
    to_port     = 88
    description = "Kerberos"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 88
    to_port     = 88
    description = "Kerberos"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 123
    to_port     = 123
    description = "Windows Time"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 135
    to_port     = 135
    description = "RPC"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 138
    to_port     = 138
    description = "Netlogon"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 389
    to_port     = 389
    description = "LDAP"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 389
    to_port     = 389
    description = "LDAP"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 445
    to_port     = 445
    description = "SMB"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 445
    to_port     = 445
    description = "SMB"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 464
    to_port     = 464
    description = "Kerberos Set & Change Password"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 464
    to_port     = 464
    description = "Kerberos Set & Change Password"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 636
    to_port     = 636
    description = "LDAP over SSL"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 3268
    to_port     = 3269
    description = "LDAP Global Catalog & GC with SSL"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 3389
    to_port     = 3389
    description = "RDP"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 5985
    to_port     = 5986
    description = "WinRM"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 9389
    to_port     = 9389
    description = " SOAP ADWS"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 49152
    to_port     = 65535
    description = "Random RPC"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 49152
    to_port     = 65535
    description = "Random RPC"
    protocol    = "UDP"
    cidr_blocks = "10.0.0.0/24"
  }
]

fsx_ports = [
  {
    from_port   = 445
    to_port     = 445
    description = "SMB"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 5985
    to_port     = 5986
    description = "WinRM"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  }
]

ms_ports = [
  {
    from_port   = 3389
    to_port     = 3389
    description = "RDP"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 5985
    to_port     = 5986
    description = "WinRM"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  }
]

pki_ports = [
  {
    from_port   = 135
    to_port     = 135
    description = "RPC"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 3389
    to_port     = 3389
    description = "RDP"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 5985
    to_port     = 5986
    description = "WinRM"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  },
  {
    from_port   = 49152
    to_port     = 65535
    description = "Random RPC"
    protocol    = "TCP"
    cidr_blocks = "10.0.0.0/24"
  }
]

r53_ports = [
  {
    from_port   = 53
    to_port     = 53
    description = "DNS"
    protocol    = "TCP"
    cidr_blocks = "0.0.0.0/0"
  },
  {
    from_port   = 53
    to_port     = 53
    description = "DNS"
    protocol    = "UDP"
    cidr_blocks = "0.0.0.0/0"
  },
]
