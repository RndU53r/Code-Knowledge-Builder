#include "order_service.h"
#include <httplib.h>

std::string OrderService::place(const std::string &item)
{
    httplib::Client cli("http://billing");
    cli.Post("/charge", item, "text/plain");
    return repo_->save(item);
}
