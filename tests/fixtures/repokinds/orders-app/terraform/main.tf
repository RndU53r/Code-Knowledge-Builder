resource "aws_ecs_service" "orders" {
  name = "orders"
}
resource "aws_lb" "orders" {
  name = "orders"
}
resource "aws_s3_bucket" "invoices" {
  bucket = "orders-invoices"
}
resource "aws_sqs_queue" "events" {
  name = "orders-events"
}
