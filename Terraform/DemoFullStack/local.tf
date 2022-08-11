locals {
  ad_ports = [
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 88
      to_port     = 88
      description = "Kerberos"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 88
      to_port     = 88
      description = "Kerberos"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 123
      to_port     = 123
      description = "Windows Time"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 135
      to_port     = 135
      description = "RPC"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 138
      to_port     = 138
      description = "Netlogon"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 389
      to_port     = 389
      description = "LDAP"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 389
      to_port     = 389
      description = "LDAP"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 464
      to_port     = 464
      description = "Kerberos Set & Change Password"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 464
      to_port     = 464
      description = "Kerberos Set & Change Password"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 636
      to_port     = 636
      description = "LDAP over SSL"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 3268
      to_port     = 3269
      description = "LDAP Global Catalog & GC with SSL"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 9389
      to_port     = 9389
      description = " SOAP ADWS"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "UDP"
      cidr_blocks = var.vpc_cidr
    }
  ]

  fsx_ports = [
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    }
  ]

  ms_ports = [
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    }
  ]

  pki_ports = [
    {
      from_port   = 135
      to_port     = 135
      description = "RPC"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "TCP"
      cidr_blocks = var.vpc_cidr
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

  mad_admin_username = "admin"

  rds_admin_username = "admin"

  onprem_administrator_username = "Administrator"
}
