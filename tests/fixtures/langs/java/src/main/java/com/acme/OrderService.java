package com.acme;

import org.springframework.stereotype.Service;

@Service
public class OrderService {
    private final OrderRepo repo;

    public OrderService(OrderRepo repo) {
        this.repo = repo;
    }

    public String place(String item) {
        return repo.save(item);
    }
}
