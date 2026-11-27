#include "order_controller.h"

void OrderController::create(const Pistache::Rest::Request &req, Pistache::Http::ResponseWriter res)
{
    if (!authorize(req)) {
        res.send(Pistache::Http::Code::Unauthorized);
        return;
    }
    std::string item = req.body();
    service_->place(item);
    res.send(Pistache::Http::Code::Ok, "ok");
}
