import yaml
from django.db import connection
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.safestring import mark_safe


def order_detail(request, pk):
    q = "SELECT * FROM shop_order WHERE id = " + request.GET["id"]
    with connection.cursor() as cur:
        cur.execute(q)
    return HttpResponse(mark_safe(request.GET.get("note", "")))


class SearchView:
    def get(self, request):
        cfg = yaml.load(request.body)
        return redirect(request.GET["next"])
