output "default_route_table_id" {
  value = aws_vpc.main.default_route_table_id
}

output "nat_subnet1_id" {
  value = aws_subnet.nat_subnet1.id
}

output "nat_subnet2_id" {
  value = aws_subnet.nat_subnet2.id
}

output "nat_subnet3_id" {
  value = aws_subnet.nat_subnet3.id
}

output "private_subnet1_id" {
  value = aws_subnet.private_subnet1.id
}

output "private_subnet2_id" {
  value = aws_subnet.private_subnet2.id
}

output "private_subnet3_id" {
  value = aws_subnet.private_subnet3.id
}

output "public_subnet1_id" {
  value = aws_subnet.public_subnet1.id
}

output "public_subnet2_id" {
  value = aws_subnet.public_subnet2.id
}

output "public_subnet3_id" {
  value = aws_subnet.public_subnet3.id
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "nat1_route_table_id" {
  value = aws_route_table.nat1.id
}

output "nat2_route_table_id" {
  value = aws_route_table.nat2.id
}

output "nat3_route_table_id" {
  value = aws_route_table.nat3.id
}

output "private_route_table_id" {
  value = aws_route_table.private.id
}

output "public_route_table_id" {
  value = aws_route_table.public.id
}