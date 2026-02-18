locals {
  ecr_repo_health     = "${var.ecr_project_name}-health-lambda"
  ecr_repo_authorizer = "${var.ecr_project_name}-authorizer-lambda"
}
