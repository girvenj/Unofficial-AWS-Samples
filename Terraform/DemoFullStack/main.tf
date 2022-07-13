data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

resource "random_string" "random_string" {
  length  = 8
  special = false
  upper   = false
}
