package web

import (
	"net/http"

	"example.com/shop/internal/service"
	"github.com/go-chi/chi/v5"
)

type OrderHandler struct {
	svc *service.OrderService
}

func (h *OrderHandler) Create(w http.ResponseWriter, r *http.Request) {
	item := r.URL.Query().Get("item")
	h.svc.Place(item)
}

func Routes(h *OrderHandler) http.Handler {
	r := chi.NewRouter()
	r.With(auth).Post("/orders", h.Create)
	return r
}
