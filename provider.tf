terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.13.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.10.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
