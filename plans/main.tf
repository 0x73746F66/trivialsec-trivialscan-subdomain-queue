provider "aws" {
  region              = local.aws_default_region
  secret_key          = var.aws_secret_access_key
  access_key          = var.aws_access_key_id
  allowed_account_ids = [local.aws_master_account_id]
}

terraform {
  required_version = ">= 1.1.7"

  required_providers {
    local = {
      source  = "hashicorp/local"
      version = ">= 2.2.2"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.9.0"
    }
  }
  backend "s3" {}
}
