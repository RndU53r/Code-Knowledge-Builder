#pragma once
#include <string>
#include "order_repo.h"

class OrderService {
public:
    std::string place(const std::string &item);

private:
    OrderRepo *repo_;
};
