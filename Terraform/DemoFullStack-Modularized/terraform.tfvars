aws_region_primary                            = "us-west-2"
aws_region_secondary                          = "us-east-2"
cad_size                                      = "Large"
default_ec2_instance_type                     = "t3.large"
ec2_ami_name                                  = "Windows_Server-2022-English-Full-Base*"
ec2_ami_owner                                 = "amazon"
ebs_kms_key                                   = "ebs-key"
fsx_kms_key                                   = "fsx-key"
fsx_mad_alias                                 = "FSx-MAD"
fsx_mad_automatic_backup_retention_days       = 7
fsx_mad_deployment_type                       = "SINGLE_AZ_2"
fsx_mad_storage_capacity                      = 32
fsx_mad_storage_type                          = "SSD"
fsx_mad_throughput_capacity                   = 16
fsx_self_alias                                = "FSx-Self"
fsx_self_automatic_backup_retention_days      = 7
fsx_self_deployment_type                      = "SINGLE_AZ_2"
fsx_self_storage_capacity                     = 32
fsx_self_storage_type                         = "SSD"
fsx_self_throughput_capacity                  = 16
mad_desired_number_of_domain_controllers      = 2
mad_domain_fqdn                               = "corp.example.com"
mad_domain_netbios                            = "CORP"
mad_edition                                   = "Enterprise"
mad_mgmt_server_netbios_name                  = "MAD-MGMT01"
mad_trust_direction                           = "One-Way: Outgoing"
onprem_child_dc_server_netbios_name           = "CHILD-DC01"
onprem_child_domain_netbios                   = "CHILD"
onprem_root_additional_dc_server_netbios_name = "ONPREM-DC02"
onprem_root_dc_adc_svc_username               = "AdcServiceAccount"
onprem_root_dc_deploy_adc                     = true
onprem_root_dc_deploy_fsx                     = true
onprem_root_dc_domain_fqdn                    = "onpremises.local"
onprem_root_dc_domain_netbios                 = "ONPREMISES"
onprem_root_dc_fsx_administrators_group       = "FSxAdmins"
onprem_root_dc_fsx_ou                         = "DC=onpremises,DC=local"
onprem_root_dc_fsx_svc_username               = "FSxServiceAccount"
onprem_root_dc_server_netbios_name            = "ONPREM-DC01"
onprem_root_pki_server_netbios_name           = "ONPREM-PKI01"
patch_group_tag                               = "Patches-All-DailyCheck-TF"
r53_resolver_name                             = "Demo-VPC-Resolver"
rds_allocated_storage                         = 20
rds_engine                                    = "sqlserver-se"
rds_engine_version                            = "15.00.4198.2.v1"
rds_identifier                                = "rds-mad"
rds_instance_class                            = "db.t3.xlarge"
rds_kms_key                                   = "rds-key"
rds_port_number                               = 1433
rds_storage_type                              = "gp2"
rds_username                                  = "admin"
secret_kms_key                                = "secret-key"
ssm_association_approve_after_days            = 0
ssm_association_deployment_rate               = "rate(12 Hours)"
ssm_association_inventory_rate                = "rate(6 Hours)"
ssm_association_max_concurrency               = "50%"
ssm_association_max_errors                    = "100%"
use_customer_managed_keys                     = true
vpc_cidr_primary                              = "10.0.0.0/24"
vpc_cidr_secondary                            = "10.1.0.0/24"
vpc_name_primary                              = "Demo-VPC"
vpc_name_secondary                            = "Demo-VPC"
