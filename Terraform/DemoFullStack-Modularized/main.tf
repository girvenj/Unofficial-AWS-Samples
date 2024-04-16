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

data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

data "aws_iam_policy_document" "amazon_ssm_managed_ec2_instance_default_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "random_string" "random_string" {
  length  = 6
  numeric = true
  special = false
  upper   = false
}

resource "aws_iam_role" "amazon_ssm_managed_ec2_instance_default_role" {
  name               = "Amazon-SSM-Managed-EC2-Instance-Default-Role-${random_string.random_string.result}"
  assume_role_policy = data.aws_iam_policy_document.amazon_ssm_managed_ec2_instance_default_role.json
  managed_policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy"
  ]
  tags = {
    Name = "Amazon-SSM-Managed-EC2-Instance-Default-Role-${random_string.random_string.result}"
  }
}

resource "aws_ssm_service_setting" "default_role" {
  setting_id    = "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role"
  setting_value = "service-role/${aws_iam_role.amazon_ssm_managed_ec2_instance_default_role.name}"
}

resource "aws_launch_template" "main" {
  name = "Metadata-Config-Launch-Template-${random_string.random_string.result}"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }
}

module "ssm_docs" {
  source                 = "./modules/ssm-docs"
  ssm_docs_random_string = random_string.random_string.result
}

module "ssm_updates_software" {
  source                                       = "./modules/ssm-associations"
  ssm_association_approve_after_days           = var.ssm_association_approve_after_days
  ssm_association_driver_deployment_rate       = var.ssm_association_driver_deployment_rate
  ssm_association_launch_agent_deployment_rate = var.ssm_association_launch_agent_deployment_rate
  ssm_association_patching_deployment_rate     = var.ssm_association_patching_deployment_rate
  ssm_association_ssm_agent_deployment_rate    = var.ssm_association_ssm_agent_deployment_rate
  ssm_association_inventory_rate               = var.ssm_association_inventory_rate
  ssm_association_max_concurrency              = var.ssm_association_max_concurrency
  ssm_association_max_errors                   = var.ssm_association_max_errors
  ssm_association_patch_group_tag              = "${var.patch_group_tag}-${random_string.random_string.result}"
  ssm_association_random_string                = random_string.random_string.result
}

module "network" {
  source            = "./modules/vpc-core"
  vpc_cidr          = var.vpc_cidr_primary
  vpc_name          = var.vpc_name_primary
  vpc_random_string = random_string.random_string.result
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

/*module "r53_outbound_resolver" {
  source                      = "./modules/r53-resolver"
  r53_create_inbound_resolver = var.r53_deploy_inbound_resolver
  r53_resolver_name           = var.r53_resolver_name
  r53_resolver_random_string  = random_string.random_string.result
  r53_resolver_subnet_ids     = [module.network.nat_subnet1_id, module.network.nat_subnet2_id]
  r53_resolver_vpc_id         = module.network.vpc_id
}

module "managed_ad" {
  source                                   = "./modules/ds-mad"
  mad_desired_number_of_domain_controllers = var.mad_desired_number_of_domain_controllers
  mad_domain_fqdn                          = var.mad_domain_fqdn
  mad_domain_netbios                       = var.mad_domain_netbios
  mad_edition                              = var.mad_edition
  mad_random_string                        = random_string.random_string.result
  mad_subnet_ids                           = [module.network.nat_subnet1_id, module.network.nat_subnet2_id]
  mad_vpc_id                               = module.network.vpc_id
}

module "mad_trust" {
  source                                                = "./modules/ds-mad-trust"
  mad_trust_directory_id                                = module.managed_ad.managed_ad_id
  mad_trust_mad_domain_dns_name                         = var.mad_domain_fqdn
  mad_trust_mad_domain_resolver                         = module.managed_ad.managed_ad_ips
  mad_trust_onpremises_domain_dns_name                  = var.onprem_root_dc_domain_fqdn
  mad_trust_onpremises_domain_netbios_name              = var.onprem_root_dc_domain_netbios
  mad_trust_onpremises_domain_resolver                  = [module.onprem_root_dc_instance.onprem_ad_ip]
  mad_trust_direction                                   = var.mad_trust_direction
  mad_trust_secret_arn                                  = module.managed_ad.managed_ad_password_secret_arn
  mad_trust_secret_kms_key_arn                          = module.managed_ad.managed_ad_password_secret_kms_key_arn
  mad_trust_random_string                               = random_string.random_string.result
  mad_trust_onpremises_administrator_secret_arn         = module.onprem_root_dc_instance.onprem_ad_password_secret_arn
  mad_trust_onpremises_administrator_secret_kms_key_arn = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  mad_trust_ssm_target_iam_role                         = module.onprem_root_dc_instance.onprem_ad_iam_role_name
  mad_trust_ssm_target_instance_id                      = module.onprem_root_dc_instance.onprem_ad_instance_id
}

module "mad_mgmt_instance" {
  source                        = "./modules/ec2-mgmt"
  mad_mgmt_admin_secret         = module.managed_ad.managed_ad_password_secret_id
  mad_mgmt_admin_secret_kms_key = module.managed_ad.managed_ad_password_secret_kms_alias_name
  mad_mgmt_deploy_pki           = true
  mad_mgmt_dns_resolver_ip      = module.managed_ad.managed_ad_ips
  mad_mgmt_domain_fqdn          = module.managed_ad.managed_ad_domain_name
  mad_mgmt_domain_netbios       = module.managed_ad.managed_ad_netbios_name
  mad_mgmt_ec2_ami_name         = var.ec2_ami_name
  mad_mgmt_ec2_ami_owner        = var.ec2_ami_owner
  mad_mgmt_ec2_instance_type    = var.default_ec2_instance_type
  mad_mgmt_ec2_launch_template  = aws_launch_template.main.id
  mad_mgmt_ebs_kms_key          = module.kms_ebs_key.kms_alias_name
  mad_mgmt_patch_group_tag      = "${var.patch_group_tag}-${random_string.random_string.result}"
  mad_mgmt_random_string        = random_string.random_string.result
  mad_mgmt_security_group_id    = module.pki_security_group_primary.sg_id
  mad_mgmt_server_netbios_name  = var.mad_mgmt_server_netbios_name
  mad_mgmt_ssm_docs             = [module.ssm_docs.ssm_initial_doc_name, module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  mad_mgmt_subnet_id            = module.network.nat_subnet1_id
  mad_mgmt_vpc_cidr             = module.network.vpc_cidr
}

module "r53_outbound_resolver_rule_mad" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_domain_name              = module.managed_ad.managed_ad_domain_name
  r53_rule_name                     = replace("${module.managed_ad.managed_ad_domain_name}", ".", "-")
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_outbound_endpoint_id
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
  fsx_mad_directory_netbios_name          = var.mad_domain_netbios
  fsx_mad_random_string                   = random_string.random_string.result
  fsx_mad_setup_secret_arn                = module.managed_ad.managed_ad_password_secret_arn
  fsx_mad_storage_capacity                = var.fsx_mad_storage_capacity
  fsx_mad_storage_type                    = var.fsx_mad_storage_type
  fsx_mad_subnet_ids                      = [module.network.nat_subnet1_id]
  fsx_mad_throughput_capacity             = var.fsx_mad_throughput_capacity
  fsx_mad_vpc_id                          = module.network.vpc_id
  setup_ec2_iam_role                      = module.mad_mgmt_instance.managed_ad_mgmt_iam_role_name
  setup_secret_arn                        = module.managed_ad.managed_ad_password_secret_arn
  setup_secret_kms_key_arn                = module.managed_ad.managed_ad_password_secret_kms_key_arn
  setup_ssm_target_instance_id            = module.mad_mgmt_instance.managed_ad_mgmt_instance_id
}

module "rds_mad" {
  source                = "./modules/rds-mssql-mad"
  rds_allocated_storage = var.rds_allocated_storage
  rds_directory_id      = module.managed_ad.managed_ad_id
  rds_engine            = var.rds_engine
  rds_engine_version    = var.rds_engine_version
  rds_identifier        = var.rds_identifier
  rds_instance_class    = var.rds_instance_class
  rds_port_number       = var.rds_port_number
  rds_random_string     = random_string.random_string.result
  rds_storage_type      = var.rds_storage_type
  rds_subnet_ids        = [module.network.nat_subnet1_id, module.network.nat_subnet2_id]
  rds_username          = var.rds_username
  rds_vpc_id            = module.network.vpc_id
}*/

module "kms_ebs_key" {
  source                          = "./modules/kms"
  kms_key_description             = "KMS key for EBS encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "ebs-key"
  kms_multi_region                = false
  kms_random_string               = random_string.random_string.result
}

module "onprem_root_dc_instance" {
  source                             = "./modules/ec2-root-dc"
  onprem_root_dc_deploy_fsx          = var.onprem_root_dc_deploy_fsx
  onprem_root_dc_domain_fqdn         = var.onprem_root_dc_domain_fqdn
  onprem_root_dc_domain_netbios      = var.onprem_root_dc_domain_netbios
  onprem_root_dc_ebs_kms_key         = module.kms_ebs_key.kms_alias_name
  onprem_root_dc_ec2_ami_name        = var.ec2_ami_name
  onprem_root_dc_ec2_ami_owner       = var.ec2_ami_owner
  onprem_root_dc_ec2_instance_type   = var.default_ec2_instance_type
  onprem_root_dc_ec2_launch_template = aws_launch_template.main.id
  onprem_root_dc_patch_group_tag     = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_root_dc_random_string       = random_string.random_string.result
  onprem_root_dc_security_group_id   = module.ad_security_group_primary.sg_id
  onprem_root_dc_server_netbios_name = var.onprem_root_dc_server_netbios_name
  onprem_root_dc_ssm_docs            = [module.ssm_docs.ssm_initial_doc_name, module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_root_dc_subnet_id           = module.network.nat_subnet1_id
  onprem_root_dc_vpc_cidr            = module.network.vpc_cidr
  depends_on = [
    module.network
  ]
}

/*module "connect_ad" {
  source                       = "./modules/ds-cad"
  cad_dns_ips                  = [module.onprem_root_dc_instance.onprem_ad_ip]
  cad_domain_fqdn              = module.onprem_root_dc_instance.onprem_ad_domain_name
  cad_domain_netbios_name      = module.onprem_root_dc_instance.onprem_ad_netbios_name
  cad_parent_ou_dn             = "OU=AWS Applications,DC=onpremises,DC=local"
  cad_random_string            = random_string.random_string.result
  cad_svc_username             = "adc_svc"
  cad_size                     = var.cad_size
  cad_subnet_ids               = [module.network.nat_subnet1_id, module.network.nat_subnet2_id]
  cad_vpc_id                   = module.network.vpc_id
  setup_ec2_iam_role           = module.onprem_root_dc_instance.onprem_ad_iam_role_name
  setup_secret_arn             = module.onprem_root_dc_instance.onprem_ad_password_secret_arn
  setup_secret_kms_key_arn     = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  setup_ssm_target_instance_id = module.onprem_root_dc_instance.onprem_ad_instance_id
}

module "r53_outbound_resolver_rule_onprem_root" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_name                     = replace("${module.onprem_root_dc_instance.onprem_ad_domain_name}", ".", "-")
  r53_rule_domain_name              = module.onprem_root_dc_instance.onprem_ad_domain_name
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_outbound_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = [module.onprem_root_dc_instance.onprem_ad_ip]
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "fsx_onpremises" {
  source                                    = "./modules/fsx-self-managed"
  fsx_self_alias                            = var.fsx_self_alias
  fsx_self_automatic_backup_retention_days  = var.fsx_self_automatic_backup_retention_days
  fsx_self_deployment_type                  = var.fsx_self_deployment_type
  fsx_self_domain_fqdn                      = module.onprem_root_dc_instance.onprem_ad_domain_name
  fsx_self_domain_netbios_name              = module.onprem_root_dc_instance.onprem_ad_netbios_name
  fsx_self_dns_ips                          = [module.onprem_root_dc_instance.onprem_ad_ip]
  fsx_self_parent_ou_dn                     = "OU=AWS Applications,DC=onpremises,DC=local"
  fsx_self_file_system_administrators_group = "FSxAdmins"
  fsx_self_random_string                    = random_string.random_string.result
  fsx_self_run_location                     = "DomainController"
  fsx_self_storage_capacity                 = var.fsx_self_storage_capacity
  fsx_self_storage_type                     = var.fsx_self_storage_type
  fsx_self_subnet_ids                       = [module.network.nat_subnet1_id]
  fsx_self_throughput_capacity              = 16
  fsx_self_username                         = "FSxSvcAct"
  fsx_self_vpc_id                           = module.network.vpc_id
  setup_ec2_iam_role                        = module.onprem_root_dc_instance.onprem_ad_iam_role_name
  setup_secret_arn                          = module.onprem_root_dc_instance.onprem_ad_password_secret_arn
  setup_secret_kms_key_arn                  = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  setup_ssm_target_instance_id              = module.onprem_root_dc_instance.onprem_ad_instance_id
  depends_on = [
    #module.connect_ad
  ]
}*/

module "rds_onpremises" {
  source                        = "./modules/rds-mssql-self-managed"
  rds_self_allocated_storage    = var.rds_self_allocated_storage
  rds_self_engine               = var.rds_self_engine
  rds_self_engine_version       = var.rds_self_engine_version
  rds_self_identifier           = var.rds_self_identifier
  rds_self_instance_class       = var.rds_self_instance_class
  rds_self_port_number          = var.rds_self_port_number
  rds_self_random_string        = random_string.random_string.result
  rds_self_storage_type         = var.rds_self_storage_type
  rds_self_subnet_ids           = [module.network.nat_subnet1_id, module.network.nat_subnet2_id]
  rds_self_username             = var.rds_self_username
  rds_self_vpc_id               = module.network.vpc_id
  setup_ec2_iam_role            = module.onprem_root_dc_instance.onprem_ad_iam_role_name
  setup_secret_arn              = module.onprem_root_dc_instance.onprem_ad_password_secret_arn
  setup_secret_kms_key_arn      = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  setup_ssm_target_instance_id  = module.onprem_root_dc_instance.onprem_ad_instance_id
  rds_self_dns_ips              = [module.onprem_root_dc_instance.onprem_ad_ip, "10.0.0.2"]
  rds_self_domain_netbios_name  = module.onprem_root_dc_instance.onprem_ad_netbios_name
  rds_self_domain_fqdn          = module.onprem_root_dc_instance.onprem_ad_domain_name
  rds_self_administrators_group = "RDSAdmins"
  rds_self_parent_ou_dn         = "OU=AWS Applications,DC=onpremises,DC=local"
  rds_self_svc_account_username = "RDSSvcAct"
  depends_on = [
    #module.connect_ad
  ]
}

/*module "onprem_pki_instance" {
  source                              = "./modules/ec2-pki"
  onprem_administrator_secret         = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  onprem_domain_fqdn                  = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_domain_netbios               = module.onprem_root_dc_instance.onprem_ad_netbios_name
  onprem_pki_dns_resolver_ip          = [module.onprem_root_dc_instance.onprem_ad_ip]
  onprem_pki_ebs_kms_key              = module.kms_ebs_key.kms_alias_name
  onprem_pki_ec2_ami_name             = var.ec2_ami_name
  onprem_pki_ec2_ami_owner            = var.ec2_ami_owner
  onprem_pki_ec2_instance_type        = var.default_ec2_instance_type
  onprem_pki_ec2_launch_template      = aws_launch_template.main.id
  onprem_pki_patch_group_tag          = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_pki_random_string            = random_string.random_string.result
  onprem_pki_security_group_id        = module.pki_security_group_primary.sg_id
  onprem_pki_server_netbios_name      = var.onprem_root_pki_server_netbios_name
  onprem_pki_ssm_docs                 = [module.ssm_docs.ssm_initial_doc_name, module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_pki_subnet_id                = module.network.nat_subnet1_id
  onprem_pki_vpc_cidr                 = module.network.vpc_cidr
}

module "onprem_child_dc_instance" {
  source                              = "./modules/ec2-child-dc"
  onprem_administrator_secret         = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  onprem_domain_dns_resolver_ip       = [module.onprem_root_dc_instance.onprem_ad_ip]
  onprem_domain_fqdn                  = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_child_dc_ebs_kms_key         = module.kms_ebs_key.kms_alias_name
  onprem_child_dc_ec2_ami_name        = var.ec2_ami_name
  onprem_child_dc_ec2_ami_owner       = var.ec2_ami_owner
  onprem_child_dc_ec2_instance_type   = var.default_ec2_instance_type
  onprem_child_dc_ec2_launch_template = aws_launch_template.main.id
  onprem_child_dc_patch_group_tag     = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_child_dc_random_string       = random_string.random_string.result
  onprem_child_dc_security_group_id   = module.ad_security_group_primary.sg_id
  onprem_child_dc_server_netbios_name = var.onprem_child_dc_server_netbios_name
  onprem_child_dc_ssm_docs            = [module.ssm_docs.ssm_initial_doc_name, module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_child_dc_subnet_id           = module.network.nat_subnet1_id
  onprem_child_dc_vpc_cidr            = module.network.vpc_cidr
  onprem_child_domain_netbios         = var.onprem_child_domain_netbios
}

module "r53_outbound_resolver_rule_onprem_child" {
  source                            = "./modules/r53-outbound-resolver-rule"
  r53_rule_name                     = replace("${module.onprem_child_dc_instance.onprem_child_ad_domain_name}", ".", "-")
  r53_rule_domain_name              = module.onprem_child_dc_instance.onprem_child_ad_domain_name
  r53_rule_r53_outbound_resolver_id = module.r53_outbound_resolver.resolver_outbound_endpoint_id
  r53_rule_random_string            = random_string.random_string.result
  r53_rule_target_ip                = [module.onprem_child_dc_instance.child_onprem_ad_ip]
  r53_rule_vpc_id                   = module.network.vpc_id
}

module "onprem_additional_root_dc_instance" {
  source                                   = "./modules/ec2-additional-dc"
  onprem_administrator_secret              = module.onprem_root_dc_instance.onprem_ad_password_secret_id
  onprem_administrator_secret_kms_key      = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
  onprem_domain_dns_resolver_ip            = [module.onprem_root_dc_instance.onprem_ad_ip]
  onprem_domain_fqdn                       = module.onprem_root_dc_instance.onprem_ad_domain_name
  onprem_domain_netbios                    = module.onprem_root_dc_instance.onprem_ad_netbios_name
  onprem_additional_dc_ebs_kms_key         = module.kms_ebs_key.kms_alias_name
  onprem_additional_dc_ec2_ami_name        = var.ec2_ami_name
  onprem_additional_dc_ec2_ami_owner       = var.ec2_ami_owner
  onprem_additional_dc_ec2_instance_type   = var.default_ec2_instance_type
  onprem_additional_dc_ec2_launch_template = aws_launch_template.main.id
  onprem_additional_dc_patch_group_tag     = "${var.patch_group_tag}-${random_string.random_string.result}"
  onprem_additional_dc_random_string       = random_string.random_string.result
  onprem_additional_dc_security_group_id   = module.ad_security_group_primary.sg_id
  onprem_additional_dc_server_netbios_name = var.onprem_root_additional_dc_server_netbios_name
  onprem_additional_dc_ssm_docs            = [module.ssm_docs.ssm_initial_doc_name, module.ssm_docs.ssm_baseline_doc_name, module.ssm_docs.ssm_auditpol_doc_name, module.ssm_docs.ssm_pki_doc_name]
  onprem_additional_dc_subnet_id           = module.network.nat_subnet1_id
  onprem_additional_dc_vpc_cidr            = module.network.vpc_cidr
}

/*resource "aws_launch_template" "secondary" {
  provider = aws.secondary
  name      = "Metadata-Config-Launch-Template-${random_string.random_string.result}"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }
}

module "ssm_updates_software_secondary" {
  source                                       = "./modules/ssm-associations"
  providers                                    = { aws = aws.secondary }
  ssm_association_approve_after_days           = var.ssm_association_approve_after_days
  ssm_association_driver_deployment_rate       = var.ssm_association_driver_deployment_rate
  ssm_association_launch_agent_deployment_rate = var.ssm_association_launch_agent_deployment_rate
  ssm_association_patching_deployment_rate     = var.ssm_association_patching_deployment_rate
  ssm_association_ssm_agent_deployment_rate    = var.ssm_association_ssm_agent_deployment_rate
  ssm_association_inventory_rate               = var.ssm_association_inventory_rate
  ssm_association_max_concurrency              = var.ssm_association_max_concurrency
  ssm_association_max_errors                   = var.ssm_association_max_errors
  ssm_association_patch_group_tag              = "${var.patch_group_tag}-${random_string.random_string.result}"
  ssm_association_random_string                = random_string.random_string.result
}

module "network_secondary" {
  source            = "./modules/vpc-core"
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
  source             = "./modules/vpc-peer"
  peer_region        = var.aws_region_secondary
  peer_vpc_cidr      = module.network_secondary.vpc_cidr
  peer_vpc_id        = module.network_secondary.vpc_id
  peer_vpc_nat1_rt   = module.network_secondary.nat1_route_table_id
  peer_vpc_nat2_rt   = module.network_secondary.nat2_route_table_id
  peer_vpc_nat3_rt   = module.network_secondary.nat3_route_table_id
  peer_vpc_public_rt = module.network_secondary.public_route_table_id
  vpc_cidr           = module.network.vpc_cidr
  vpc_id             = module.network.vpc_id
  vpc_nat1_rt        = module.network.nat1_route_table_id
  vpc_nat2_rt        = module.network.nat2_route_table_id
  vpc_nat3_rt        = module.network.nat3_route_table_id
  vpc_public_rt      = module.network.public_route_table_id
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

module "managed_ad_new_region" {
  providers = {
    aws.primary   = aws.primary
    aws.secondary = aws.secondary
  }
  source                                              = "./modules/ds-mad-new-region"
  mad_new_region_desired_number_of_domain_controllers = var.mad_desired_number_of_domain_controllers
  mad_new_region_directory_id                         = module.managed_ad.managed_ad_id
  mad_new_region_domain_fqdn                          = var.mad_domain_fqdn
  mad_new_region_random_string                        = random_string.random_string.result
  mad_new_region_region_name                          = var.aws_region_secondary
  mad_new_region_subnet_ids                           = [module.network_secondary.nat_subnet1_id, module.network_secondary.nat_subnet2_id]
  mad_new_region_vpc_id                               = module.network_secondary.vpc_id
  depends_on = [
    module.fsx_mad
  ]
}*/
