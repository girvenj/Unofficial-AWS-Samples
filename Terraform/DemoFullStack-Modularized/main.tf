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
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 53
      to_port     = 53
      description = "DNS"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 88
      to_port     = 88
      description = "Kerberos"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 88
      to_port     = 88
      description = "Kerberos"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 123
      to_port     = 123
      description = "Windows Time"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 135
      to_port     = 135
      description = "RPC"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 138
      to_port     = 138
      description = "Netlogon"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 389
      to_port     = 389
      description = "LDAP"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 389
      to_port     = 389
      description = "LDAP"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 464
      to_port     = 464
      description = "Kerberos Set & Change Password"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 464
      to_port     = 464
      description = "Kerberos Set & Change Password"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 636
      to_port     = 636
      description = "LDAP over SSL"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 3268
      to_port     = 3269
      description = "LDAP Global Catalog & GC with SSL"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 9389
      to_port     = 9389
      description = " SOAP ADWS"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "UDP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    }
  ]

  ms_ports = [
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    }
  ]

  pki_ports = [
    {
      from_port   = 135
      to_port     = 135
      description = "RPC"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 3389
      to_port     = 3389
      description = "RDP"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]

    },
    {
      from_port   = 49152
      to_port     = 65535
      description = "Random RPC"
      protocol    = "TCP"
      cidr_blocks = [var.vpc_cidr_primary, var.vpc_cidr_secondary]
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
  vpc_cidr          = var.vpc_cidr_primary
  vpc_name          = var.vpc_name_primary
  vpc_random_string = random_string.random_string.result
}

module "network_secondary" {
  source            = "./modules/network-core"
  providers         = { aws = aws.secondary }
  vpc_cidr          = var.vpc_cidr_secondary
  vpc_name          = var.vpc_name_secondary
  vpc_random_string = random_string.random_string.result
}

module "network_peer" {
  providers = {
    aws.primary   = aws.primary
    aws.secondary = aws.secondary
  }
  source                          = "./modules/network-peer"
  peer_vpc_cidr                   = module.network_secondary.vpc_cidr
  peer_vpc_default_route_table_id = module.network_secondary.default_route_table_id
  peer_vpc_id                     = module.network_secondary.vpc_id
  peer_region                     = var.aws_region_secondary
  vpc_cidr                        = module.network.vpc_cidr
  vpc_default_route_table_id      = module.network.default_route_table_id
  vpc_id                          = module.network.vpc_id
}

module "r53_outbound_resolver" {
  source                     = "./modules/r53-outbound-resolver"
  r53_resolver_name          = var.r53_resolver_name
  r53_resolver_random_string = random_string.random_string.result
  r53_resolver_subnet_ids    = [module.network.subnet1_id, module.network.subnet2_id]
  r53_resolver_vpc_id        = module.network.vpc_id
}

module "managed_ad" {
  source                                   = "./modules/mad"
  mad_desired_number_of_domain_controllers = var.mad_desired_number_of_domain_controllers
  mad_domain_fqdn                          = var.mad_domain_fqdn
  mad_domain_netbios                       = var.mad_domain_netbios
  mad_edition                              = var.mad_edition
  mad_random_string                        = random_string.random_string.result
  mad_secret_kms_key                       = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  mad_subnet_ids                           = [module.network.subnet1_id, module.network.subnet2_id]
  mad_vpc_id                               = module.network.vpc_id
}

/*
module "managed_ad_new_region" {
  providers = {
    aws.primary   = aws.primary
    aws.secondary = aws.secondary
  }
  source                                              = "./modules/mad-new-region"
  mad_new_region_desired_number_of_domain_controllers = var.mad_desired_number_of_domain_controllers
  mad_new_region_directory_id                         = module.managed_ad.managed_ad_id
  mad_new_region_domain_fqdn                          = var.mad_domain_fqdn
  mad_new_region_random_string                        = random_string.random_string.result
  mad_new_region_region_name                          = var.aws_region_secondary
  mad_new_region_subnet_ids                           = [module.network_secondary.subnet1_id, module.network_secondary.subnet2_id]
  mad_new_region_vpc_id                               = module.network_secondary.vpc_id
}*/

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
  fsx_mad_alias                           = var.fsx_mad_alias
  fsx_mad_automatic_backup_retention_days = var.fsx_mad_automatic_backup_retention_days
  fsx_mad_deployment_type                 = var.fsx_mad_deployment_type
  fsx_mad_directory_id                    = module.managed_ad.managed_ad_id
  fsx_mad_kms_key                         = var.use_customer_managed_keys ? module.kms_fsx_key[0].kms_alias_name : "alias/aws/fsx"
  fsx_mad_random_string                   = random_string.random_string.result
  fsx_mad_storage_capacity                = var.fsx_mad_storage_capacity
  fsx_mad_storage_type                    = var.fsx_mad_storage_type
  fsx_mad_subnet_ids                      = [module.network.subnet1_id]
  fsx_mad_throughput_capacity             = var.fsx_mad_throughput_capacity
  fsx_mad_vpc_id                          = module.network.vpc_id
}

module "rds_mad" {
  source                = "./modules/rds-mssql"
  rds_allocated_storage = var.rds_allocated_storage
  rds_directory_id      = module.managed_ad.managed_ad_id
  rds_engine            = var.rds_engine
  rds_engine_version    = var.rds_engine_version
  rds_identifier        = var.rds_identifier
  rds_instance_class    = var.rds_instance_class
  rds_kms_key           = var.use_customer_managed_keys ? module.kms_rds_key[0].kms_alias_name : "alias/aws/rds"
  rds_port_number       = var.rds_port_number
  rds_random_string     = random_string.random_string.result
  rds_secret_kms_key    = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  rds_storage_type      = var.rds_storage_type
  rds_subnet_ids        = [module.network.subnet1_id, module.network.subnet2_id]
  rds_username          = var.rds_username
  rds_vpc_id            = module.network.vpc_id
}

module "ssm_docs" {
  source                 = "./modules/ssm-docs"
  ssm_docs_random_string = random_string.random_string.result
}

module "ad_security_group_primary" {
  source      = "./modules/vpc-security-group-ingress"
  description = "AD-Server-Security Group"
  name        = "AD-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ad_ports
  vpc_id      = module.network.vpc_id
}

module "ms_security_group_primary" {
  source      = "./modules/vpc-security-group-ingress"
  description = "Member Server Security Group"
  name        = "Member-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ms_ports
  vpc_id      = module.network.vpc_id
}

module "pki_security_group_primary" {
  source      = "./modules/vpc-security-group-ingress"
  description = "PKI Server Security Group"
  name        = "PKI-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.pki_ports
  vpc_id      = module.network.vpc_id
}

module "ad_security_group_secondary" {
  source      = "./modules/vpc-security-group-ingress"
  providers   = { aws = aws.secondary }
  description = "AD-Server-Security Group"
  name        = "AD-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ad_ports
  vpc_id      = module.network_secondary.vpc_id
}

module "ms_security_group_secondary" {
  source      = "./modules/vpc-security-group-ingress"
  providers   = { aws = aws.secondary }
  description = "Member Server Security Group"
  name        = "Member-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.ms_ports
  vpc_id      = module.network_secondary.vpc_id
}

module "pki_security_group_secondary" {
  source      = "./modules/vpc-security-group-ingress"
  providers   = { aws = aws.secondary }
  description = "PKI Server Security Group"
  name        = "PKI-Server-Security-Group-${random_string.random_string.result}"
  ports       = local.pki_ports
  vpc_id      = module.network_secondary.vpc_id
}

module "kms_ebs_key" {
  count                           = var.use_customer_managed_keys ? 1 : 0
  source                          = "./modules/kms"
  kms_key_description             = "KMS key for EBS encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = var.ebs_kms_key
  kms_random_string               = random_string.random_string.result
}

module "kms_rds_key" {
  count                           = var.use_customer_managed_keys ? 1 : 0
  source                          = "./modules/kms"
  kms_key_description             = "KMS key for RDS encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = var.rds_kms_key
  kms_random_string               = random_string.random_string.result
}

module "kms_fsx_key" {
  count                           = var.use_customer_managed_keys ? 1 : 0
  source                          = "./modules/kms"
  kms_key_description             = "KMS key for FSx encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = var.fsx_kms_key
  kms_random_string               = random_string.random_string.result
}

module "kms_secret_key" {
  count                           = var.use_customer_managed_keys ? 1 : 0
  source                          = "./modules/kms"
  kms_key_description             = "KMS key for Secret encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = var.secret_kms_key
  kms_random_string               = random_string.random_string.result
}

module "onprem_root_dc_instance" {
  source                                  = "./modules/ec2-root-dc"
  mad_domain_fqdn                         = module.managed_ad.managed_ad_domain_name
  mad_admin_secret                        = module.managed_ad.managed_ad_password_secret_id
  onprem_root_dc_deploy_fsx               = true
  onprem_root_dc_domain_fqdn              = var.onprem_root_dc_domain_fqdn
  onprem_root_dc_domain_netbios           = var.onprem_root_dc_domain_netbios
  onprem_root_dc_ebs_kms_key              = var.use_customer_managed_keys ? module.kms_ebs_key[0].kms_alias_name : "alias/aws/ebs"
  onprem_root_dc_ec2_ami_name             = var.ec2_ami_name
  onprem_root_dc_ec2_ami_owner            = var.ec2_ami_owner
  onprem_root_dc_fsx_ou                   = var.onprem_root_dc_fsx_ou
  onprem_root_dc_fsx_administrators_group = var.onprem_root_dc_fsx_administrators_group
  onprem_root_dc_fsx_svc_username         = var.onprem_root_dc_fsx_svc_username
  onprem_root_dc_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_root_dc_random_string            = random_string.random_string.result
  onprem_root_dc_secret_kms_key           = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  onprem_root_dc_use_customer_managed_key = var.use_customer_managed_keys
  onprem_root_dc_security_group_id        = module.ad_security_group_primary.sg_id
  onprem_root_dc_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_root_dc_subnet_id                = module.network.subnet1_id
  mad_trust_direction                     = var.mad_trust_direction
  onprem_root_dc_vpc_cidr                 = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_mad
  ]
}

module "r53_outbound_resolver_rule_onprem_root" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_name                     = replace("${module.onprem_root_dc_instance.onprem_ad_domain_name}", ".", "-")
  r53_rule_domain_name              = module.onprem_root_dc_instance.onprem_ad_domain_name
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = [module.onprem_root_dc_instance.onprem_ad_ip]
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "mad_mgmt_instance" {
  source                            = "./modules/ec2-mgmt"
  mad_mgmt_admin_secret             = module.managed_ad.managed_ad_password_secret_id
  mad_mgmt_admin_secret_kms_key     = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  mad_mgmt_deploy_pki               = false
  mad_mgmt_directory_id             = module.managed_ad.managed_ad_id
  mad_mgmt_domain_fqdn              = module.managed_ad.managed_ad_domain_name
  mad_mgmt_domain_netbios           = module.managed_ad.managed_ad_netbios_name
  mad_mgmt_ec2_ami_name             = var.ec2_ami_name
  mad_mgmt_ec2_ami_owner            = var.ec2_ami_owner
  mad_mgmt_ebs_kms_key              = var.use_customer_managed_keys ? module.kms_ebs_key[0].kms_alias_name : "alias/aws/ebs"
  mad_mgmt_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  mad_mgmt_random_string            = random_string.random_string.result
  mad_mgmt_security_group_id        = module.ms_security_group_primary.sg_id
  mad_mgmt_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  mad_mgmt_subnet_id                = module.network.subnet1_id
  mad_mgmt_use_customer_managed_key = var.use_customer_managed_keys
  mad_mgmt_vpc_cidr                 = module.network.vpc_cidr
  onprem_domain_fqdn                = module.onprem_root_dc_instance.onprem_ad_domain_name
  mad_trust_direction               = module.onprem_root_dc_instance.mad_trust_direction
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "fsx_onpremises" {
  source                                    = "./modules/fsx-self-managed"
  fsx_self_alias                            = var.fsx_self_alias
  fsx_self_automatic_backup_retention_days  = var.fsx_self_automatic_backup_retention_days
  fsx_self_deployment_type                  = var.fsx_self_deployment_type
  fsx_self_domain_fqdn                      = module.onprem_root_dc_instance.onprem_ad_domain_name
  fsx_self_dns_ips                          = [module.onprem_root_dc_instance.onprem_ad_ip]
  fsx_self_parent_ou_dn                     = module.onprem_root_dc_instance.onprem_ad_fsx_ou
  fsx_self_file_system_administrators_group = module.onprem_root_dc_instance.onprem_ad_fsx_admin
  fsx_self_kms_key                          = var.use_customer_managed_keys ? module.kms_fsx_key[0].kms_alias_name : "alias/aws/fsx"
  fsx_self_password_secret                  = module.onprem_root_dc_instance.onprem_ad_fsx_svc_password_secret_id
  fsx_self_random_string                    = random_string.random_string.result
  fsx_self_storage_capacity                 = var.fsx_self_storage_capacity
  fsx_self_storage_type                     = var.fsx_self_storage_type
  fsx_self_subnet_ids                       = [module.network.subnet1_id]
  fsx_self_throughput_capacity              = 16
  fsx_self_username                         = var.onprem_root_dc_fsx_svc_username
  fsx_self_vpc_id                           = module.network.vpc_id
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "onprem_pki_instance" {
  source                              = "./modules/ec2-pki"
  onprem_administrator_secret         = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  onprem_domain_fqdn                  = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_domain_netbios               = module.onprem_root_dc_instance.onprem_ad_netbios_name
  onprem_pki_ebs_kms_key              = var.use_customer_managed_keys ? module.kms_ebs_key[0].kms_alias_name : "alias/aws/ebs"
  onprem_pki_ec2_ami_name             = var.ec2_ami_name
  onprem_pki_ec2_ami_owner            = var.ec2_ami_owner
  onprem_pki_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_pki_random_string            = random_string.random_string.result
  onprem_pki_security_group_id        = module.pki_security_group_primary.sg_id
  onprem_pki_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_pki_subnet_id                = module.network.subnet1_id
  onprem_pki_use_customer_managed_key = var.use_customer_managed_keys
  onprem_pki_vpc_cidr                 = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "onprem_child_dc_instance" {
  source                                   = "./modules/ec2-child-dc"
  onprem_administrator_secret              = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key      = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  onprem_dc_ip                             = module.onprem_root_dc_instance.onprem_ad_ip
  onprem_domain_fqdn                       = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_child_dc_ebs_kms_key              = var.use_customer_managed_keys ? module.kms_ebs_key[0].kms_alias_name : "alias/aws/ebs"
  onprem_child_dc_ec2_ami_name             = var.ec2_ami_name
  onprem_child_dc_ec2_ami_owner            = var.ec2_ami_owner
  onprem_child_dc_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_child_dc_random_string            = random_string.random_string.result
  onprem_child_dc_security_group_id        = module.ad_security_group_primary.sg_id
  onprem_child_dc_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_child_dc_subnet_id                = module.network.subnet1_id
  onprem_child_dc_vpc_cidr                 = module.network.vpc_cidr
  onprem_child_dc_use_customer_managed_key = var.use_customer_managed_keys
  onprem_child_domain_netbios              = "CHILD"
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
  source                                        = "./modules/ec2-additional-dc"
  onprem_administrator_secret                   = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key           = var.use_customer_managed_keys ? module.kms_secret_key[0].kms_alias_name : "alias/aws/secretsmanager"
  onprem_dc_ip                                  = module.onprem_root_dc_instance.onprem_ad_ip
  onprem_domain_fqdn                            = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_domain_netbios                         = module.onprem_root_dc_instance.onprem_ad_netbios_name
  onprem_additional_dc_ebs_kms_key              = var.use_customer_managed_keys ? module.kms_ebs_key[0].kms_alias_name : "alias/aws/ebs"
  onprem_additional_dc_ec2_ami_name             = var.ec2_ami_name
  onprem_additional_dc_ec2_ami_owner            = var.ec2_ami_owner
  onprem_additional_dc_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_additional_dc_random_string            = random_string.random_string.result
  onprem_additional_dc_security_group_id        = module.ad_security_group_primary.sg_id
  onprem_additional_dc_ssm_docs                 = [module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_additional_dc_subnet_id                = module.network.subnet1_id
  onprem_additional_dc_use_customer_managed_key = var.use_customer_managed_keys
  onprem_additional_dc_vpc_cidr                 = module.network.vpc_cidr
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_root
  ]
}

module "ssm-updates_software" {
  source                             = "./modules/ssm-associations"
  ssm_association_approve_after_days = var.ssm_association_approve_after_days
  ssm_association_deployment_rate    = var.ssm_association_deployment_rate
  ssm_association_inventory_rate     = var.ssm_association_inventory_rate
  ssm_association_max_concurrency    = var.ssm_association_max_concurrency
  ssm_association_max_errors         = var.ssm_association_max_errors
  ssm_association_patch_group_tag    = "${var.patch_group_tag}-${random_string.random_string.result}"
  ssm_association_random_string      = random_string.random_string.result
  depends_on = [
    module.r53_outbound_resolver_rule_onprem_child
  ]
}

resource "aws_ssm_association" "fsx_mad_alias" {
  name             = module.ssm_docs.ssm_fsx_alias_doc_name
  association_name = "FSx-MAD-${random_string.random_string.result}"
  parameters = {
    Alias             = var.fsx_mad_alias
    ARecord           = module.fsx_mad.managed_ad_fsx_dns_name
    DomainNetBIOSName = module.managed_ad.managed_ad_netbios_name
    RunLocation       = "MemberServer"
    SecretArn         = module.managed_ad.managed_ad_password_secret_id
  }
  targets {
    key    = "InstanceIds"
    values = [module.mad_mgmt_instance.managed_ad_mgmt_instance_id]
  }
}

resource "aws_ssm_association" "fsx_onpremises_alias" {
  name             = module.ssm_docs.ssm_fsx_alias_doc_name
  association_name = "FSx-Onpremises-${random_string.random_string.result}"
  parameters = {
    Alias       = var.fsx_self_alias
    ARecord     = module.fsx_onpremises.self_managed_ad_fsx_dns_name
    RunLocation = "DomainController"
  }
  targets {
    key    = "InstanceIds"
    values = [module.onprem_root_dc_instance.onprem_ad_instance_id]
  }
}
