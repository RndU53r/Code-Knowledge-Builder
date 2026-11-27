#include <pistache/endpoint.h>
#include <pistache/router.h>
#include "order_controller.h"

using namespace Pistache;

int main()
{
    Rest::Router router;
    OrderController ctl;
    Routes::Post(router, "/orders", Routes::bind(&OrderController::create, &ctl));
    Http::Endpoint server(Address(Ipv4::any(), Port(8080)));
    server.setHandler(router.handler());
    server.serve();
    return 0;
}
