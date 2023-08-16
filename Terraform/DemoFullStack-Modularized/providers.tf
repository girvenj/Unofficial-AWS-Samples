terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region_primary
}

provider "aws" {
  alias  = "primary"
  region = var.aws_region_primary
}

provider "aws" {
  alias  = "secondary"
  region = var.aws_region_secondary
}
