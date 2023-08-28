terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

locals {
  aws_ssm_association_drivers = [
    {
      friendly_name = "AWS-ENA-Driver"
      name          = "AwsEnaNetworkDriver"
    },
    {
      friendly_name = "AWS-NVMe-Driver"
      name          = "AWSNVMe"
    },
    {
      friendly_name = "AWS-PV-Driver"
      name          = "AWSPVDriver"
    }
  ]

  aws_ssm_patchbaselinelinux = [
    {
      friendly_name    = "AlmaLinux"
      operating_system = "ALMA_LINUX"
    },
    {
      friendly_name    = "Amazon-Linux"
      operating_system = "AMAZON_LINUX"
    },
    {
      friendly_name    = "Amazon-Linux-2"
      operating_system = "AMAZON_LINUX_2"
    },
    {
      friendly_name    = "Amazon-Linux-2022"
      operating_system = "AMAZON_LINUX_2022"
    },
    {
      friendly_name    = "Amazon-Linux-2023"
      operating_system = "AMAZON_LINUX_2023"
    },
    {
      friendly_name    = "CentOS-Linux"
      operating_system = "CENTOS"
    },
    {
      friendly_name    = "Oracle-Linux"
      operating_system = "ORACLE_LINUX"
    },
    {
      friendly_name    = "RedHat-Linux"
      operating_system = "REDHAT_ENTERPRISE_LINUX"
    },
    {
      friendly_name    = "Rocky-Linux"
      operating_system = "ROCKY_LINUX"
    }
  ]

  aws_ssm_patchbaselinedebian = [
    {
      friendly_name    = "Debian-Linux"
      operating_system = "DEBIAN"
    },
    {
      friendly_name    = "Raspbian-Linux"
      operating_system = "RASPBIAN"
    },
    {
      friendly_name    = "Ubuntu-Linux"
      operating_system = "UBUNTU"
    }
  ]

  aws_ssm_patchbaselineother = [
    {
      friendly_name    = "Mac"
      operating_system = "MACOS"
    },
    {
      friendly_name    = "Suse-Linux"
      operating_system = "SUSE"
    }
  ]
}

resource "aws_ssm_patch_baseline" "linux" {
  description      = "This baseline includes patches for all ${each.key} operating systems and products and runs every day"
  for_each         = { for bl in local.aws_ssm_patchbaselinelinux : bl.friendly_name => bl }
  name             = "${each.key}-Patches-All-DailyCheck-${var.ssm_association_random_string}"
  operating_system = each.value.operating_system
  approval_rule {
    approve_after_days  = var.ssm_association_approve_after_days
    compliance_level    = "CRITICAL"
    enable_non_security = true
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["*"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
    patch_filter {
      key    = "SEVERITY"
      values = ["*"]
    }
  }
}

resource "aws_ssm_default_patch_baseline" "linux" {
  baseline_id      = aws_ssm_patch_baseline.linux[each.key].id
  for_each         = { for bl in local.aws_ssm_patchbaselinelinux : bl.friendly_name => bl }
  operating_system = aws_ssm_patch_baseline.linux[each.key].operating_system
}

resource "aws_ssm_patch_group" "linux" {
  baseline_id = aws_ssm_patch_baseline.linux[each.key].id
  for_each    = { for bl in local.aws_ssm_patchbaselinelinux : bl.friendly_name => bl }
  patch_group = var.ssm_association_patch_group_tag
}

resource "aws_ssm_patch_baseline" "debian" {
  description      = "This baseline includes patches for all ${each.key} operating systems and products and runs every day"
  for_each         = { for bl in local.aws_ssm_patchbaselinedebian : bl.friendly_name => bl }
  name             = "${each.key}-Patches-All-DailyCheck-${var.ssm_association_random_string}"
  operating_system = each.value.operating_system
  approval_rule {
    approve_after_days  = var.ssm_association_approve_after_days
    compliance_level    = "CRITICAL"
    enable_non_security = true
    patch_filter {
      key    = "PRIORITY"
      values = ["*"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
    patch_filter {
      key    = "SECTION"
      values = ["*"]
    }
  }
}

resource "aws_ssm_default_patch_baseline" "debian" {
  baseline_id      = aws_ssm_patch_baseline.debian[each.key].id
  for_each         = { for bl in local.aws_ssm_patchbaselinedebian : bl.friendly_name => bl }
  operating_system = aws_ssm_patch_baseline.debian[each.key].operating_system
}

resource "aws_ssm_patch_group" "debian" {
  baseline_id = aws_ssm_patch_baseline.debian[each.key].id
  for_each    = { for bl in local.aws_ssm_patchbaselinedebian : bl.friendly_name => bl }
  patch_group = var.ssm_association_patch_group_tag
}

resource "aws_ssm_patch_baseline" "other" {
  description      = "This baseline includes patches for all ${each.key} operating systems and products and runs every day"
  for_each         = { for bl in local.aws_ssm_patchbaselineother : bl.friendly_name => bl }
  name             = "${each.key}-Patches-All-DailyCheck-${var.ssm_association_random_string}"
  operating_system = each.value.operating_system
  approval_rule {
    approve_after_days  = var.ssm_association_approve_after_days
    compliance_level    = "CRITICAL"
    enable_non_security = false
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["*"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
  }
}

resource "aws_ssm_default_patch_baseline" "other" {
  baseline_id      = aws_ssm_patch_baseline.other[each.key].id
  for_each         = { for bl in local.aws_ssm_patchbaselineother : bl.friendly_name => bl }
  operating_system = aws_ssm_patch_baseline.other[each.key].operating_system
}

resource "aws_ssm_patch_group" "other" {
  baseline_id = aws_ssm_patch_baseline.other[each.key].id
  for_each    = { for bl in local.aws_ssm_patchbaselineother : bl.friendly_name => bl }
  patch_group = var.ssm_association_patch_group_tag
}

resource "aws_ssm_patch_baseline" "windows" {
  description      = "This baseline includes patches for all Microsoft operating systems and products and runs every day"
  name             = "Microsoft-Patches-All-DailyCheck-${var.ssm_association_random_string}"
  operating_system = "WINDOWS"
  approval_rule {
    approve_after_days  = var.ssm_association_approve_after_days
    compliance_level    = "CRITICAL"
    enable_non_security = false
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["*"]
    }
    patch_filter {
      key    = "MSRC_SEVERITY"
      values = ["*"]
    }
    patch_filter {
      key    = "PATCH_SET"
      values = ["OS"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
  }

  approval_rule {
    approve_after_days  = var.ssm_association_approve_after_days
    compliance_level    = "CRITICAL"
    enable_non_security = false
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["*"]
    }
    patch_filter {
      key    = "MSRC_SEVERITY"
      values = ["*"]
    }
    patch_filter {
      key    = "PATCH_SET"
      values = ["APPLICATION"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
    patch_filter {
      key    = "PRODUCT_FAMILY"
      values = ["*"]
    }
  }
}

resource "aws_ssm_default_patch_baseline" "windows" {
  baseline_id      = aws_ssm_patch_baseline.windows.id
  operating_system = aws_ssm_patch_baseline.windows.operating_system
}

resource "aws_ssm_patch_group" "windows" {
  baseline_id = aws_ssm_patch_baseline.windows.id
  patch_group = var.ssm_association_patch_group_tag
}

resource "aws_ssm_association" "drivers" {
  for_each                    = { for dr in local.aws_ssm_association_drivers : dr.friendly_name => dr }
  apply_only_at_cron_interval = true
  association_name            = "${each.key}-DailyCheck-${var.ssm_association_random_string}"
  compliance_severity         = "HIGH"
  max_concurrency             = var.ssm_association_max_concurrency
  max_errors                  = var.ssm_association_max_errors
  name                        = "AWS-ConfigureAWSPackage"
  parameters = {
    action              = "Install"
    additionalArguments = "{}"
    installationType    = "Uninstall and reinstall"
    name                = each.value.name
    version             = ""
  }
  schedule_expression = var.ssm_association_driver_deployment_rate
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

resource "aws_ssm_association" "launch-agent" {
  apply_only_at_cron_interval = false
  association_name            = "AWS-EC2Launch-Agent-DailyCheck-${var.ssm_association_random_string}"
  compliance_severity         = "HIGH"
  max_concurrency             = var.ssm_association_max_concurrency
  max_errors                  = var.ssm_association_max_errors
  name                        = "AWS-ConfigureAWSPackage"
  parameters = {
    action              = "Install"
    additionalArguments = "{}"
    installationType    = "Uninstall and reinstall"
    name                = "AWSEC2Launch-Agent"
    version             = ""
  }
  schedule_expression = var.ssm_association_launch_agent_deployment_rate
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

resource "aws_ssm_association" "ssm-agent" {
  apply_only_at_cron_interval = false
  association_name            = "AWS-SSMAgent-Agent-DailyCheck-${var.ssm_association_random_string}"
  compliance_severity         = "HIGH"
  max_concurrency             = var.ssm_association_max_concurrency
  max_errors                  = var.ssm_association_max_errors
  name                        = "AWS-UpdateSSMAgent"
  schedule_expression         = var.ssm_association_ssm_agent_deployment_rate
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

resource "aws_ssm_association" "software-inventory" {
  apply_only_at_cron_interval = false
  association_name            = "Gather-Software-Inventory-DailyCheck-${var.ssm_association_random_string}"
  compliance_severity         = "CRITICAL"
  name                        = "AWS-GatherSoftwareInventory"
  parameters = {
    applications                = "Enabled"
    awsComponents               = "Enabled"
    billingInfo                 = "Enabled"
    customInventory             = "Enabled"
    instanceDetailedInformation = "Enabled"
    networkConfig               = "Enabled"
    services                    = "Enabled"
    windowsRoles                = "Enabled"
    windowsUpdates              = "Enabled"
  }
  schedule_expression = var.ssm_association_inventory_rate
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

resource "aws_ssm_association" "patching" {
  apply_only_at_cron_interval = true
  association_name            = "Run-Patch-Baseline-DailyCheck-${var.ssm_association_random_string}"
  compliance_severity         = "CRITICAL"
  name                        = "AWS-RunPatchBaseline"
  parameters = {
    Operation    = "Install"
    RebootOption = "RebootIfNeeded"
  }
  schedule_expression = var.ssm_association_patching_deployment_rate
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

/*resource "aws_ssm_maintenance_window" "main" {
  allow_unassociated_targets = true
  cutoff                     = 0
  duration                   = 1
  name                       = "Patches-All-DailyCheck-${var.ssm_association_random_string}"
  schedule                   = "rate(12 Hours)"
}

resource "aws_ssm_maintenance_window_target" "main" {
  name          = "Patches-All-DailyCheck-${var.ssm_association_random_string}"
  resource_type = "INSTANCE"
  window_id     = aws_ssm_maintenance_window.main.id
  targets {
    key    = "tag:PatchGroup"
    values = [var.ssm_association_patch_group_tag]
  }
}

resource "aws_ssm_maintenance_window_task" "main" {
  max_concurrency = var.ssm_association_max_concurrency
  max_errors      = var.ssm_association_max_errors
  name            = "Patches-All-DailyCheck-${var.ssm_association_random_string}"
  priority        = 1
  task_arn        = "AWS-RunPatchBaseline"
  task_type       = "RUN_COMMAND"
  window_id       = aws_ssm_maintenance_window.main.id
  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.main.id]
  }
  task_invocation_parameters {
    run_command_parameters {
      timeout_seconds = "600"
      parameter {
        name   = "Operation"
        values = ["Install"]
      }
      parameter {
        name   = "RebootOption"
        values = ["RebootIfNeeded"]
      }
      parameter {
        name   = "SnapshotId"
        values = ["{{WINDOW_EXECUTION_ID}}"]
      }
    }
  }
}*/

/*data "aws_iam_policy_document" "amazon_ssm_managed_ec2_instance_default_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "amazon_ssm_managed_ec2_instance_default_role" {
  name               = "Amazon-SSM-Managed-EC2-Instance-Default-Role-${var.ssm_association_random_string}"
  assume_role_policy = data.aws_iam_policy_document.amazon_ssm_managed_ec2_instance_default_role.json
  managed_policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy"
  ]
  tags = {
    Name = "Amazon-SSM-Managed-EC2-Instance-Default-Role-${var.ssm_association_random_string}"
  }
}

resource "aws_ssm_service_setting" "test_setting" {
  setting_id    = "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role"
  setting_value = "service-role/${aws_iam_role.amazon_ssm_managed_ec2_instance_default_role.name}"
}*/
