static ngx_int_t ngx_http_orders_handler(ngx_http_request_t *r) { return NGX_OK; }
static char *ngx_http_orders(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_orders_handler;
    return NGX_CONF_OK;
}
