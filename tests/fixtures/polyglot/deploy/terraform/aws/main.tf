# AWS infra for the shop (fixture; never apply)
provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "invoices" {
  bucket = "shop-invoices-fixture"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket            = aws_s3_bucket.invoices.id
  block_public_acls = false
}

resource "aws_security_group" "gateway" {
  name = "gateway-sg"
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "shop" {
  identifier        = "shop-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
  username          = "orders"
  password          = var.db_password
}

resource "aws_mq_broker" "orders" {
  broker_name        = "orders"
  engine_type        = "RabbitMQ"
  engine_version     = "3.11.20"
  host_instance_type = "mq.t3.micro"
  publicly_accessible = false
  user {
    username = "fulfillment"
    password = var.mq_password
  }
}

resource "aws_iam_policy" "orders_app" {
  name   = "orders-app"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", "Action" : "*", Resource = "*" }]
  })
}

variable "db_password" { sensitive = true }
variable "mq_password" { sensitive = true }
