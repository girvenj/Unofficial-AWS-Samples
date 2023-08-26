output "resolver_inbound_endpoint_id" {
  value = join("", aws_route53_resolver_endpoint.r53_inbound_resolver[*].id)
}

output "resolver_outbound_endpoint_id" {
  value = aws_route53_resolver_endpoint.r53_outbound_resolver.id
}