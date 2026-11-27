#include "auth.h"

bool authorize(const Pistache::Rest::Request &req)
{
    auto header = req.headers().tryGet<Pistache::Http::Header::Authorization>();
    return header != nullptr;
}
