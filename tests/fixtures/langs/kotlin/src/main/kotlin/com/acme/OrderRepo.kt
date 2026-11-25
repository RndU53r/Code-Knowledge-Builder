package com.acme

import org.springframework.web.client.RestTemplate

open class BaseRepo {
    open fun save(item: String): String {
        return item
    }
}

class OrderRepo(private val conn: java.sql.Connection, private val http: RestTemplate) : BaseRepo() {
    override fun save(item: String): String {
        http.getForObject("http://billing/charge", String::class.java)
        conn.createStatement().executeQuery("SELECT * FROM orders WHERE id = " + item)
        return super.save(item)
    }
}
