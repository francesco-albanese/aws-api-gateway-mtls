# Lambda function for health endpoint
# Minimal function to test mTLS - returns client cert info when available

data "archive_file" "health_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda/health.zip"

  source {
    content  = <<-EOF
      import json

      def handler(event, context):
          # Extract mTLS client certificate info from request context
          request_context = event.get("requestContext", {})
          authentication = request_context.get("authentication", {})
          client_cert = authentication.get("clientCert", {})

          response_body = {
              "status": "healthy",
              "mtls": {
                  "enabled": bool(client_cert),
                  "clientCN": client_cert.get("subjectDN", "").split("CN=")[-1].split(",")[0] if client_cert else None,
                  "serialNumber": client_cert.get("serialNumber"),
                  "validity": client_cert.get("validity", {})
              }
          }

          return {
              "statusCode": 200,
              "headers": {"Content-Type": "application/json"},
              "body": json.dumps(response_body)
          }
    EOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "health" {
  function_name    = "mtls-api-health"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.health_lambda.output_path
  source_code_hash = data.archive_file.health_lambda.output_base64sha256

  tags = {
    Name = "mtls-api-health"
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "mtls-api-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "mtls-api-lambda-exec"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/*/*"
}

# API Gateway integration and route
resource "aws_apigatewayv2_integration" "health" {
  api_id                 = aws_apigatewayv2_api.mtls_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.health.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "health" {
  api_id    = aws_apigatewayv2_api.mtls_api.id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.health.id}"
}
