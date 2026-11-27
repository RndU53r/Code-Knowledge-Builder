#include <stdio.h>
#include <signal.h>
#include "civetweb.h"
#include "handlers.h"

static void on_term(int sig)
{
    printf("stopping\n");
}

int main(int argc, char **argv)
{
    struct mg_context *ctx = mg_start(NULL, NULL, NULL);
    signal(SIGTERM, on_term);
    mg_set_request_handler(ctx, "/orders", create_order_handler, NULL);
    return 0;
}
