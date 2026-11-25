package com.acme

import io.ktor.server.routing.*

fun Route.orderRoutes(service: OrderService) {
    authenticate("auth") {
        post("/ktor/orders") {
            service.place(call.receiveText())
        }
    }
}
