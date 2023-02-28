terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_secretsmanager_secret_version" "main" {
  secret_id = var.cad_password_secret
}

resource "aws_directory_service_directory" "main" {
  name     = var.cad_domain_fqdn
  password = jsondecode(data.aws_secretsmanager_secret_version.main.secret_string)["password"]
  short_name = var.cad_domain_netbios_name
  size       = var.cad_size
  type       = "ADConnector"
  tags = {
    Name = "${var.cad_domain_fqdn}-CAD-${var.cad_random_string}"
  }
  connect_settings {
    customer_dns_ips  = var.cad_dns_ips
    customer_username = jsondecode(data.aws_secretsmanager_secret_version.main.secret_string)["username"]
    subnet_ids        = var.cad_subnet_ids
    vpc_id            = var.cad_vpc_id
  }
}
