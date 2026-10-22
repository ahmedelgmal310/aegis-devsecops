terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.70"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project    = var.name
      ManagedBy  = "terraform"
      Repository = var.github_repository
    }
  }
}
