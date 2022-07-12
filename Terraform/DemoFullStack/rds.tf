data "aws_iam_policy_document" "rds_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds" {
  count               = var.mad_deploy_rds ? 1 : 0
  name                = "RDS-Domain-IAM-Role-${random_string.random_string.result}"
  assume_role_policy  = data.aws_iam_policy_document.rds_instance_assume_role_policy.json
  managed_policy_arns = ["arn:${data.aws_partition.main.partition}:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"]
  tags = {
    Name = "RDS-Domain-IAM-Role-${random_string.random_string.result}"
  }
  depends_on = [
    data.aws_iam_policy_document.rds_instance_assume_role_policy
  ]
}

resource "aws_db_subnet_group" "rds" {
  count      = var.mad_deploy_rds ? 1 : 0
  name       = "rds-subnet-group-${random_string.random_string.result}"
  subnet_ids = [aws_subnet.network_subnet1.id, aws_subnet.network_subnet2.id]
  tags = {
    Name = "RDS-Subnet-Group"
  }
  depends_on = [
    aws_subnet.network_subnet1,
    aws_subnet.network_subnet2
  ]
}

resource "aws_security_group" "rds" {
  count       = var.mad_deploy_rds ? 1 : 0
  name        = "RDS-Security-Group-${random_string.random_string.result}"
  description = "RDS Security Group"
  ingress {
    description = "SQL Inbound from VPC"
    from_port   = 1433
    to_port     = 1433
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.network.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "RDS-Security-Group-${random_string.random_string.result}"
  }
  vpc_id = aws_vpc.network.id
  depends_on = [
    aws_vpc.network
  ]
}

resource "aws_db_instance" "rds" {
  count                = var.mad_deploy_rds ? 1 : 0
  allocated_storage    = 20
  availability_zone    = data.aws_availability_zones.available.names[0]
  db_subnet_group_name = aws_db_subnet_group.rds[0].id
  domain               = aws_directory_service_directory.mad.id
  domain_iam_role_name = aws_iam_role.rds[0].name
  engine               = "sqlserver-se"
  engine_version       = "15.00.4198.2.v1"
  identifier           = "demo-rds-mad"
  instance_class       = "db.t3.xlarge"
  license_model        = "license-included"
  multi_az             = false
  password             = random_password.secret_rds.result
  port                 = "1433"
  skip_final_snapshot  = true
  storage_type         = "gp2"
  tags = {
    Name = "DemoRDSMad-${random_string.random_string.result}"
  }
  vpc_security_group_ids = [aws_security_group.rds[0].id]
  username = "admin"
  depends_on = [
    aws_db_subnet_group.rds,
    aws_directory_service_directory.mad,
    aws_iam_role.rds,
    aws_security_group.rds,
    random_password.secret_rds,
  ]
}
