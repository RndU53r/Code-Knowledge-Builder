package com.acme;

import java.sql.Connection;
import java.sql.Statement;
import org.springframework.web.client.RestTemplate;

public class OrderRepo extends BaseRepo implements Repo {
    private final RestTemplate http = new RestTemplate();
    private final Connection conn;

    public OrderRepo(Connection conn) {
        this.conn = conn;
    }

    @Override
    public String save(String item) {
        http.getForObject("http://billing/charge", String.class);
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM orders WHERE id = " + item);
        return super.save(item);
    }
}
