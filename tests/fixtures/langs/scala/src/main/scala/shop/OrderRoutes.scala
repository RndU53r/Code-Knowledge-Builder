package shop

import akka.http.scaladsl.server.Directives._

class OrderRoutes(service: OrderService) {
  val routes = path("orders") {
    post {
      authenticateBasic("shop", authenticator) { user =>
        entity(as[String]) { body =>
          complete(service.place(body))
        }
      }
    }
  }
}
