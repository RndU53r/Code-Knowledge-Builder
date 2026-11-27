#include <event2/http.h>
#include <microhttpd.h>
#include "mongoose.h"
#include <getopt.h>

static void orders_cb(struct evhttp_request *req, void *arg) {
    const char *uri = evhttp_request_get_uri(req);
    printf(uri);
}

static int answer(void *cls, struct MHD_Connection *c, const char *url, const char *method, const char *version, const char *data, size_t *size, void **ptr) {
    if (strcmp(url, "/items") == 0 && strcmp(method, "POST") == 0) {
        return 0;
    }
    return 1;
}

static void ev(struct mg_connection *conn, int ev, void *ev_data) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, "/api/v1/stock")) {
        system(hm->body.ptr);
    }
}

int main(int argc, char **argv) {
    int opt = getopt(argc, argv, "p:");
    evhttp_set_cb(http, "/api/orders", orders_cb, NULL);
    return 0;
}
