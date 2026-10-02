terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Credentials for this provider are for the tooling/build account, not production.
provider "aws" {
  region = "ap-south-1"
}
