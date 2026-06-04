terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
  backend "s3" {
    bucket = "backend-doctor-state"
    key    = "state.tfstate"
    region = "us-east-1"
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "backend-doctor-public-fixture"
  acl    = "public-read"
}

resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  default = "bd_fixture_tf_password_123456"
}
