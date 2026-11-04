package handlers

import (
	"net/http"
	"strings"
)

func (h *Handler) originAllowed(origin string) bool {
	origin = strings.TrimRight(origin, "/")
	for _, o := range h.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(o, "/"), origin) {
			return true
		}
	}
	return false
}

func (h *Handler) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Add("Vary", "Origin")
			if h.originAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
