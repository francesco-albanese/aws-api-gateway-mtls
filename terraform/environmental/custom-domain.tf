# Custom domain with mTLS enforcement
# Uses truststore from S3 to validate client certificates

resource "aws_apigatewayv2_domain_name" "api" {
  domain_name = "${var.api_subdomain}.${var.domain_name}"

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.api.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  mutual_tls_authentication {
    truststore_uri = "s3://${data.aws_s3_bucket.mtls_truststore.id}/truststore.pem"
  }

  tags = {
    Name = "${var.api_subdomain}.${var.domain_name}"
  }
}

resource "aws_apigatewayv2_api_mapping" "api" {
  api_id      = aws_apigatewayv2_api.mtls_api.id
  domain_name = aws_apigatewayv2_domain_name.api.id
  stage       = aws_apigatewayv2_stage.default.id
}
