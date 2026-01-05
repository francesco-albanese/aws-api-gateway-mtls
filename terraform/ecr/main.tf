# ECR repositories for Lambda container images
# Deploy this stack BEFORE environmental stack

resource "aws_ecr_repository" "health_lambda" {
  name                 = "${var.project_name}-health-lambda"
  image_tag_mutability = "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-health-lambda"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "health_lambda" {
  repository = aws_ecr_repository.health_lambda.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}
