output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "subnet1_id" {
  value = aws_subnet.main_subnet1.id
}

output "subnet2_id" {
  value = aws_subnet.main_subnet2.id
}

output "default_route_table_id" {
  value = aws_vpc.main.default_route_table_id
}
