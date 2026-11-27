#include <stdio.h>
#include <curl/curl.h>
#include "service.h"
#include "repo.h"

int place_order(const char *item)
{
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, "http://billing/charge");
    curl_easy_perform(h);
    return save_order(item);
}
