package com.acme

class OrderService(private val repo: OrderRepo) {
    fun place(item: String): String {
        return repo.save(item)
    }
}
