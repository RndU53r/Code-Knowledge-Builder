terraform {
  backend "s3" {
    bucket = "acme-tf-state"
    key    = "prod/terraform.tfstate"
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "ci" {
  name   = "ci-deploy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "orders" {
  identifier        = "orders"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = false
}

module "network" {
  source = "git::https://github.com/acme/tf-network.git"
}
