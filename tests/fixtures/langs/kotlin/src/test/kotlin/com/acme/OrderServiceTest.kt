package com.acme

class OrderServiceTest {
    fun places() {
        OrderService(OrderRepo(null!!, null!!)).place("a")
    }
}
