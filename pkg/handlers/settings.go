package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/app/monorepo/services/auth/pkg/password"
	"github.com/app/monorepo/services/auth/pkg/store"
)

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	claims, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req UpdateProfileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	req.Name, req.UserName, req.PhoneNumber, req.Bio, req.AvatarURL =
		trimPtr(req.Name), trimPtr(req.UserName), trimPtr(req.PhoneNumber), trimPtr(req.Bio), trimPtr(req.AvatarURL)

	if req.Name != nil && len([]rune(*req.Name)) < 2 {
		writeError(w, http.StatusBadRequest, "Nama minimal 2 karakter")
		return
	}
	if msg := validateProfileFields(req.Name, req.UserName, req.PhoneNumber, req.Bio, req.AvatarURL); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.UserName != nil && *req.UserName == "" {
		req.UserName = nil
	}
	current, err := h.users.FindByID(r.Context(), claims.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Pengguna tidak ditemukan")
		return
	}
	if err != nil {
		log.Printf("update profile: gagal membaca database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	phone, bio := current.PhoneNumber, current.Bio
	if req.PhoneNumber != nil {
		phone = *req.PhoneNumber
	}
	if req.Bio != nil {
		bio = *req.Bio
	}
	upd := store.ProfileUpdate{
		Name:        req.Name,
		UserName:    req.UserName,
		AvatarURL:   req.AvatarURL,
		PhoneNumber: phone,
		Bio:         bio,
	}
	user, err := h.users.UpdateProfile(r.Context(), claims.UserID, upd)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Pengguna tidak ditemukan")
		return
	}
	if errors.Is(err, store.ErrUserNameTaken) {
		writeError(w, http.StatusConflict, "Username sudah dipakai")
		return
	}
	if err != nil {
		log.Printf("update profile: gagal mengubah database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	writeJSON(w, http.StatusOK, AuthResponse{
		Message: "Profil berhasil diperbarui",
		Data:    user,
	})
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	claims, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req ChangePasswordRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > 128 {
		writeError(w, http.StatusBadRequest, "Kata sandi baru harus 8 sampai 128 karakter")
		return
	}
	if req.NewPassword == req.OldPassword {
		writeError(w, http.StatusBadRequest, "Kata sandi baru harus berbeda dari kata sandi lama")
		return
	}
	user, err := h.users.FindByID(r.Context(), claims.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Pengguna tidak ditemukan")
		return
	}
	if err != nil {
		log.Printf("change password: gagal membaca database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	if user.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "Akun ini didaftarkan melalui Google, tidak memiliki kata sandi lama")
		return
	}
	ok, err := password.Verify(req.OldPassword, user.PasswordHash)
	if len(req.OldPassword) > maxPasswordInput || err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "Kata sandi lama tidak sesuai")
		return
	}
	newHash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Gagal memproses kata sandi baru")
		return
	}
	if err := h.users.UpdatePasswordHash(r.Context(), claims.UserID, newHash); err != nil {
		log.Printf("change password: gagal memperbarui database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	writeJSON(w, http.StatusOK, AuthResponse{Message: "Kata sandi berhasil diubah"})
}

func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	claims, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	user, err := h.users.FindByID(r.Context(), claims.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "Pengguna tidak ditemukan")
		return
	}
	if err != nil {
		log.Printf("delete account: gagal membaca database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	if user.PasswordHash != "" {
		var req DeleteAccountRequest
		if !decodeBody(w, r, &req) {
			return
		}
		ok, err := password.Verify(req.Password, user.PasswordHash)
		if len(req.Password) > maxPasswordInput || err != nil || !ok {
			writeError(w, http.StatusUnauthorized, "Kata sandi salah")
			return
		}
	}
	if err := h.users.Delete(r.Context(), claims.UserID); err != nil {
		log.Printf("delete account: gagal menghapus dari database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	h.clearCookie(w, SessionCookie)
	writeJSON(w, http.StatusOK, AuthResponse{Message: "Akun berhasil dihapus"})
}
