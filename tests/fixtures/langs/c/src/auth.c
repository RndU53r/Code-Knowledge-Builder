#include "auth.h"
#include "civetweb.h"

int require_auth(struct mg_connection *conn)
{
    const char *token = mg_get_header(conn, "Authorization");
    return token != NULL;
}
