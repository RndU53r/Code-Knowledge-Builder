#pragma once
#include <pistache/router.h>
#include "order_service.h"
#include "auth.h"

class OrderController {
public:
    void create(const Pistache::Rest::Request &req, Pistache::Http::ResponseWriter res);

private:
    OrderService *service_;
};
