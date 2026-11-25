package web

import (
	"net/http"
	"os"
	"os/exec"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
)

func Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/items/{id}", getItem)
	r.Post("/items", createItem)
	return r
}

func Legacy(m *mux.Router) {
	m.HandleFunc("/legacy", legacy).Methods("POST")
	http.HandleFunc("GET /v2/ping", ping)
}

func Register(s *grpc.Server) {
	RegisterBillingServer(s, &billing{})
}

func getItem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	data, _ := os.ReadFile("/srv/items/" + id)
	w.Write(data)
}

func createItem(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output()
	w.Write(out)
}

func legacy(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	resp, _ := http.Get(target)
	_ = resp
}

func ping(w http.ResponseWriter, r *http.Request) { w.Write([]byte("pong")) }
