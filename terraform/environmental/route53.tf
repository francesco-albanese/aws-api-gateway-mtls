# Route53 hosted zone lookup and DNS records for API Gateway custom domain
# Zone hosted in shared-services account - uses cross-account provider

data "aws_route53_zone" "main" {
  provider     = aws.route53
  name         = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "api" {
  provider = aws.route53
  zone_id  = data.aws_route53_zone.main.zone_id
  name     = "${var.api_subdomain}.${var.domain_name}"
  type     = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
