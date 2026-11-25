package com.acme

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/orders")
class OrderController(private val service: OrderService) {
    @PostMapping
    @PreAuthorize("isAuthenticated()")
    fun create(@RequestBody body: String): String {
        return service.place(body)
    }
}
