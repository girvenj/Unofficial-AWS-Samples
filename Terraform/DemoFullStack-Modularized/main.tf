data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

locals {
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
}

resource "random_string" "random_string" {
  length  = 8
  special = false
  upper   = false
}

module "network" {
  source            = "./modules/network-core"
  vpc_cidr          = "10.0.0.0/24"
  vpc_name          = "Demo"
  vpc_random_string = random_string.random_string.result
}

module "network_secondary" {
  source            = "./modules/network-core"
  providers         = { aws = aws.secondary }
  vpc_cidr          = "10.1.0.0/24"
  vpc_name          = "Demo"
  vpc_random_string = random_string.random_string.result
}

module "network_peer" {
  providers = {
    aws.src  = aws.primary
    aws.peer = aws.secondary
  }
  source                          = "./modules/network-peer"
  peer_vpc_cidr                   = module.network_secondary.vpc_cidr
  peer_vpc_default_route_table_id = module.network_secondary.default_route_table_id
  peer_vpc_id                     = module.network_secondary.vpc_id
  peer_region                     = var.second_aws_region
  vpc_cidr                        = module.network.vpc_cidr
  vpc_default_route_table_id      = module.network.default_route_table_id
  vpc_id                          = module.network.vpc_id
}

module "r53_outbound_resolver" {
  source                     = "./modules/r53-outbound-resolver"
  r53_resolver_name          = "Demo-VPC-Resolver"
  r53_resolver_random_string = random_string.random_string.result
  r53_resolver_subnet_ids    = [module.network.subnet1_id, module.network.subnet2_id]
  r53_resolver_vpc_id        = module.network.vpc_id
}

module "managed_ad" {
  source                                   = "./modules/mad"
  mad_desired_number_of_domain_controllers = 2
  mad_domain_fqdn                          = "corp.example.com"
  mad_domain_netbios                       = "CORP"
  mad_edition                              = "Enterprise"
  mad_random_string                        = random_string.random_string.result
  mad_secret_kms_key                       = "aws/secretsmanager"
  mad_subnet_ids                           = [module.network.subnet1_id, module.network.subnet2_id]
  mad_vpc_id                               = module.network.vpc_id
}

resource "aws_directory_service_region" "example" {
  directory_id = module.managed_ad.managed_ad_id
  region_name  = var.second_aws_region
  vpc_settings {
    vpc_id     = module.network_secondary.vpc_id
    subnet_ids = [module.network_secondary.subnet1_id, module.network_secondary.subnet2_id]
  }
  tags = {
    Name = "${module.managed_ad.managed_ad_domain_name}-MAD-${random_string.random_string.result}"
  }
}

module "r53_outbound_resolver_rule_mad" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_domain_name              = module.managed_ad.managed_ad_domain_name
  r53_rule_name                     = replace("${module.managed_ad.managed_ad_domain_name}", ".", "-")
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = module.managed_ad.managed_ad_ips
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "fsx_mad" {
  source                                  = "./modules/fsx-mad"
  fsx_mad_alias                           = "FSX-MAD"
  fsx_mad_automatic_backup_retention_days = 7
  fsx_mad_deployment_type                 = "SINGLE_AZ_2"
  fsx_mad_directory_id                    = module.managed_ad.managed_ad_id
  fsx_mad_kms_key                         = "aws/fsx"
  fsx_mad_random_string                   = random_string.random_string.result
  fsx_mad_storage_capacity                = 32
  fsx_mad_storage_type                    = "SSD"
  fsx_mad_subnet_ids                      = [module.network.subnet1_id]
  fsx_mad_throughput_capacity             = 16
  fsx_mad_vpc_id                          = module.network.vpc_id
}

module "rds_mad" {
  source                = "./modules/rds-mssql"
  rds_allocated_storage = 20
  rds_directory_id      = module.managed_ad.managed_ad_id
  rds_engine            = "sqlserver-se"
  rds_engine_version    = "15.00.4198.2.v1"
  rds_identifier        = "rds-mad"
  rds_instance_class    = "db.t3.xlarge"
  rds_kms_key           = "aws/rds"
  rds_port_number       = 1433
  rds_random_string     = random_string.random_string.result
  rds_secret_kms_key    = "aws/secretsmanager"
  rds_storage_type      = "gp2"
  rds_subnet_ids        = [module.network.subnet1_id, module.network.subnet2_id]
  rds_username          = "admin"
  rds_vpc_id            = module.network.vpc_id
}

module "ssm_docs" {
  source                 = "./modules/ssm-docs"
  ssm_docs_random_string = random_string.random_string.result
}

module "ad_security_group" {
  source      = "./modules/vpc-security-group-ingress"
  description = "AD-Server-Security Group"
  name        = "AD-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ad_ports
  vpc_id      = module.network.vpc_id
}

module "ms_security_group" {
  source      = "./modules/vpc-security-group-ingress"
  description = "Member Server Security Group"
  name        = "Member-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ms_ports
  vpc_id      = module.network.vpc_id
}

module "pki_security_group" {
  source      = "./modules/vpc-security-group-ingress"
  description = "PKI Server Security Group"
  name        = "PKI-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.pki_ports
  vpc_id      = module.network.vpc_id
}

module "onprem_root_instance" {
  source                                  = "./modules/ec2-root-dc"
  mad_domain_fqdn                         = "corp.example.com"
  mad_admin_secret                        = module.managed_ad.managed_ad_password_secret_id
  onprem_root_dc_deploy_fsx               = true
  onprem_root_dc_domain_fqdn              = "onpremises.local"
  onprem_root_dc_domain_netbios           = "ONPREMISES"
  onprem_root_dc_fsx_ou                   = "DC=onpremises,DC=local"
  onprem_root_dc_fsx_administrators_group = "FSxAdmins"
  onprem_root_dc_fsx_svc_username         = "FSxServiceAccount"
  onprem_root_dc_random_string            = random_string.random_string.result
  onprem_root_dc_security_group_ids       = module.ad_security_group.sg_id
  onprem_root_dc_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_root_dc_subnet_id                = module.network.subnet1_id
  mad_trust_direction                     = "None"
  onprem_root_dc_vpc_cidr                 = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_mad
  ]
}

module "r53_outbound_resolver_rule_onprem_root" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_name                     = replace("${module.onprem_root_instance.onprem_ad_domain_name}", ".", "-")
  r53_rule_domain_name              = module.onprem_root_instance.onprem_ad_domain_name
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = [module.onprem_root_instance.onprem_ad_ip]
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "mad_mgmt_instance" {
  source                      = "./modules/ec2-mgmt"
  mad_mgmt_admin_secret       = module.managed_ad.managed_ad_password_secret_id
  mad_mgmt_deploy_pki         = false
  mad_mgmt_directory_id       = module.managed_ad.managed_ad_id
  mad_mgmt_domain_fqdn        = module.managed_ad.managed_ad_domain_name
  mad_mgmt_domain_netbios     = module.managed_ad.managed_ad_netbios_name
  mad_mgmt_random_string      = random_string.random_string.result
  mad_mgmt_security_group_ids = module.ms_security_group.sg_id
  mad_mgmt_ssm_docs           = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  mad_mgmt_subnet_id          = module.network.subnet1_id
  mad_mgmt_vpc_cidr           = module.network.vpc_cidr
  onprem_domain_fqdn          = module.onprem_root_instance.onprem_ad_domain_name
  mad_trust_direction         = module.onprem_root_instance.mad_trust_direction
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "fsx_onpremises" {
  source                                    = "./modules/fsx-self-managed"
  fsx_self_alias                            = "FSX-Self"
  fsx_self_automatic_backup_retention_days  = 7
  fsx_self_deployment_type                  = "SINGLE_AZ_2"
  fsx_self_domain_fqdn                      = module.onprem_root_instance.onprem_ad_domain_name
  fsx_self_dns_ips                          = [module.onprem_root_instance.onprem_ad_ip]
  fsx_self_parent_ou_dn                     = module.onprem_root_instance.onprem_ad_fsx_ou
  fsx_self_file_system_administrators_group = module.onprem_root_instance.onprem_ad_fsx_admin
  fsx_self_kms_key                          = "aws/fsx"
  fsx_self_password_secret                  = module.onprem_root_instance.onprem_ad_fsx_svc_password_secret_id
  fsx_self_random_string                    = random_string.random_string.result
  fsx_self_storage_capacity                 = 32
  fsx_self_storage_type                     = "SSD"
  fsx_self_subnet_ids                       = [module.network.subnet1_id]
  fsx_self_throughput_capacity              = 16
  fsx_self_username                         = module.onprem_root_instance.onprem_ad_fsx_svc
  fsx_self_vpc_id                           = module.network.vpc_id
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "onprem_pki_instance" {
  source                        = "./modules/ec2-pki"
  onprem_administrator_secret   = module.onprem_root_instance.onprem_ad_password_secret_id
  onprem_domain_fqdn            = module.onprem_root_instance.onprem_ad_domain_name
  onprem_domain_netbios         = module.onprem_root_instance.onprem_ad_netbios_name
  onprem_pki_random_string      = random_string.random_string.result
  onprem_pki_security_group_ids = module.pki_security_group.sg_id
  onprem_pki_ssm_docs           = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_pki_subnet_id          = module.network.subnet1_id
  onprem_pki_vpc_cidr           = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "onprem_child_dc_instance" {
  source                             = "./modules/ec2-child-dc"
  onprem_administrator_secret        = module.onprem_root_instance.onprem_ad_password_secret_id
  onprem_dc_ip                       = module.onprem_root_instance.onprem_ad_ip
  onprem_domain_fqdn                 = module.onprem_root_instance.onprem_ad_domain_name
  onprem_child_dc_random_string      = random_string.random_string.result
  onprem_child_dc_security_group_ids = module.ad_security_group.sg_id
  onprem_child_dc_ssm_docs           = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_child_dc_subnet_id          = module.network.subnet1_id
  onprem_child_dc_vpc_cidr           = module.network.vpc_cidr
  onprem_child_domain_netbios        = "CHILD"
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "r53_outbound_resolver_rule_onprem_child" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_name                     = replace("${module.onprem_child_dc_instance.onprem_child_ad_domain_name}", ".", "-")
  r53_rule_domain_name              = module.onprem_child_dc_instance.onprem_child_ad_domain_name
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = [module.onprem_child_dc_instance.child_onprem_ad_ip]
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "onprem_additional_dc_instance" {
  source                                  = "./modules/ec2-additional-dc"
  onprem_administrator_secret             = module.onprem_root_instance.onprem_ad_password_secret_id
  onprem_dc_ip                            = module.onprem_root_instance.onprem_ad_ip
  onprem_domain_fqdn                      = module.onprem_root_instance.onprem_ad_domain_name
  onprem_domain_netbios                   = module.onprem_root_instance.onprem_ad_netbios_name
  onprem_additional_dc_random_string      = random_string.random_string.result
  onprem_additional_dc_security_group_ids = module.ad_security_group.sg_id
  onprem_additional_dc_ssm_docs           = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_additional_dc_subnet_id          = module.network.subnet1_id
  onprem_additional_dc_vpc_cidr           = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}
