package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/app/monorepo/services/auth/pkg/tokens"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("gagal menulis respons: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, AuthResponse{Message: msg})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return false
	}
	return true
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (h *Handler) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Expires:  time.Now().Add(h.cfg.SessionTTL),
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func (h *Handler) extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		if t := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")); t != "" {
			return t
		}
	}
	if cookie, err := r.Cookie(SessionCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

func (h *Handler) authenticate(r *http.Request) (*tokens.Claims, error) {
	tok := h.extractToken(r)
	if tok == "" {
		return nil, errors.New("token tidak ada")
	}
	return h.jwt.ValidateToken(tok)
}

func isMobile(client string) bool {
	return strings.EqualFold(strings.TrimSpace(client), "mobile")
}

func (h *Handler) shortCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

func (h *Handler) googleEnabled() bool {
	return h.cfg.GoogleClientID != "" && h.cfg.GoogleClientSecret != ""
}
