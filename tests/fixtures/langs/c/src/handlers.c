#include "handlers.h"
#include "service.h"
#include "auth.h"
#include "civetweb.h"

int create_order_handler(struct mg_connection *conn, void *cbdata)
{
    if (!require_auth(conn)) {
        return 401;
    }
    const struct mg_request_info *ri = mg_get_request_info(conn);
    const char *item = ri->query_string;
    place_order(item);
    return 200;
}
