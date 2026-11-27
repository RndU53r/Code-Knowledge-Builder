#include <httplib.h>
#include <crow.h>
#include <drogon/drogon.h>
#include <oatpp/web/server/api/ApiController.hpp>

void run() {
    httplib::Server svr;
    svr.Post("/orders", [](const httplib::Request &req, httplib::Response &res) {
        system(req.body.c_str());
    });
    svr.Get("/items", ItemController::list);
}

void crow_app() {
    crow::SimpleApp app;
    CROW_ROUTE(app, "/stock").methods("POST"_method)([](const crow::request &req) {
        return crow::response(200);
    });
}

class OrderCtl : public drogon::HttpController<OrderCtl> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(OrderCtl::create, "/api/orders", Post)
    METHOD_LIST_END
    void create(const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb);
};

class Api : public oatpp::web::server::api::ApiController {
    ENDPOINT("POST", "/users", createUser, BODY_DTO(Object<UserDto>, dto)) {
        return createResponse(Status::CODE_200, "ok");
    }
};

class OrderImpl final : public Order::Service {
    grpc::Status Create(grpc::ServerContext *ctx, const CreateReq *req, CreateRes *res) override {
        return grpc::Status::OK;
    }
};
