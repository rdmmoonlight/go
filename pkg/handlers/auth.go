package handlers

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/app/monorepo/services/auth/pkg/password"
	"github.com/app/monorepo/services/auth/pkg/store"
)

func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req RegisterRequest
	if !decodeBody(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	switch {
	case len([]rune(req.Name)) < 2:
		writeError(w, http.StatusBadRequest, "Nama minimal 2 karakter")
		return
	case !strings.Contains(req.Email, "@") || len(req.Email) > 254:
		writeError(w, http.StatusBadRequest, "Email tidak valid")
		return
	case len(req.Password) < 8 || len(req.Password) > 128:
		writeError(w, http.StatusBadRequest, "Kata sandi harus 8 sampai 128 karakter")
		return
	}
	hash, err := password.Hash(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Gagal memproses kata sandi")
		return
	}
	user, err := h.users.Create(r.Context(), req.Name, req.Email, hash)
	if errors.Is(err, store.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "Email sudah terdaftar")
		return
	}
	if err != nil {
		log.Printf("register: gagal menulis database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	writeJSON(w, http.StatusCreated, AuthResponse{Message: "Registration successful", Data: user})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req LoginRequest
	if !decodeBody(w, r, &req) {
		return
	}
	const invalid = "Email atau kata sandi salah"
	user, err := h.users.FindByEmail(r.Context(), req.Email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.PasswordHash == "") {
		writeError(w, http.StatusUnauthorized, invalid)
		return
	}
	if err != nil {
		log.Printf("login: gagal membaca database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	ok, err := password.Verify(req.Password, user.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, invalid)
		return
	}
	tokenStr, err := h.jwt.GenerateToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	if isMobile(req.Client) {
		writeJSON(w, http.StatusOK, AuthResponse{Message: "Mobile login successful", Token: tokenStr, Data: user})
		return
	}
	h.setSession(w, tokenStr)
	writeJSON(w, http.StatusOK, AuthResponse{Message: "Web login successful", Data: user})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	h.clearCookie(w, SessionCookie)
	writeJSON(w, http.StatusOK, AuthResponse{Message: "Logout successful"})
}

func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	claims, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized: invalid or missing token")
		return
	}
	w.Header().Set(HeaderUserID, claims.UserID)
	w.Header().Set(HeaderUserEmail, claims.Email)
	writeJSON(w, http.StatusOK, claims)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	claims, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, AuthResponse{Message: "User profile fetched successfully", Data: claims})
}
