package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPISpec []byte

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"auth-service","status":"ok"}`))
	})

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(openAPISpec)
	})

	mux.HandleFunc("/healthz", h.Healthz)
	mux.HandleFunc("/auth/register", h.Register)
	mux.HandleFunc("/auth/login", h.Login)
	mux.HandleFunc("/auth/logout", h.Logout)
	mux.HandleFunc("/auth/validate", h.Validate)
	mux.HandleFunc("/auth/me", h.Me)
	mux.HandleFunc("/auth/google-login", h.GoogleLogin)
	mux.HandleFunc("/auth/google-callback", h.GoogleCallback)
	mux.HandleFunc("/settings/profile", h.UpdateProfile)
	mux.HandleFunc("/settings/change-password", h.ChangePassword)
	mux.HandleFunc("/settings/delete-account", h.DeleteAccount)

	return h.cors(mux)
}
