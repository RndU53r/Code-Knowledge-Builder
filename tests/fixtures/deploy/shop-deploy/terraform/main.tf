resource "aws_lb" "front" {
  name     = "shop-front"
  internal = false
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.front.arn
  port              = 80
  protocol          = "HTTP"
}

resource "aws_wafv2_web_acl" "front" {
  name  = "shop-waf"
  scope = "REGIONAL"
}

resource "aws_api_gateway_method" "open" {
  rest_api_id   = "x"
  resource_id   = "y"
  http_method   = "GET"
  authorization = "NONE"
}
