// Package store mendefinisikan penyimpanan pengguna layanan auth.
// Implementasi produksi adalah PostgreSQL (postgres.go). MemoryStore hanya
// untuk tes dan tidak dipakai oleh cmd/server.
package store

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrEmailTaken    = errors.New("email sudah terdaftar")
	ErrNotFound      = errors.New("pengguna tidak ditemukan")
	ErrUserNameTaken = errors.New("username sudah dipakai")
)

type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	// Profil (settings). Kosong berarti belum diisi; tidak dikirim di JSON agar respons lama tidak berubah.
	UserName    string `json:"userName,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Bio         string `json:"bio,omitempty"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}

// ProfileUpdate memetakan UpdateProfile sumber (.NET) ke penyimpanan.
// Pointer nil berarti kolom tidak diubah.
type ProfileUpdate struct {
	Name      *string // FullName: hanya diubah bila tidak kosong (kolom name wajib terisi)
	UserName  *string // hanya diubah bila tidak kosong dan berbeda dari yang sekarang
	AvatarURL *string // hanya diubah bila tidak kosong
	// Selalu ditulis; string kosong disimpan sebagai NULL.
	PhoneNumber string
	Bio         string
}

// Store adalah kontrak penyimpanan pengguna.
type Store interface {
	// Create membuat pengguna berkata sandi. ErrEmailTaken bila email sudah ada.
	Create(ctx context.Context, name, email, passwordHash string) (*User, error)
	// FindByEmail mengembalikan ErrNotFound bila tidak ada.
	FindByEmail(ctx context.Context, email string) (*User, error)
	// UpsertExternal dipakai login Google: membuat pengguna bila belum ada.
	UpsertExternal(ctx context.Context, name, email string) (*User, error)
	// FindByID mengembalikan ErrNotFound bila tidak ada (termasuk id yang bukan UUID).
	FindByID(ctx context.Context, id string) (*User, error)
	// UpdateProfile menerapkan ProfileUpdate. ErrUserNameTaken bila username sudah dipakai pengguna lain
	// (tanpa membedakan huruf besar-kecil). ErrNotFound bila pengguna tidak ada.
	UpdateProfile(ctx context.Context, id string, upd ProfileUpdate) (*User, error)
	// UpdatePasswordHash mengganti hash kata sandi. ErrNotFound bila pengguna tidak ada.
	UpdatePasswordHash(ctx context.Context, id, passwordHash string) error
	// Delete menghapus pengguna. ErrNotFound bila pengguna tidak ada.
	Delete(ctx context.Context, id string) error
}

func normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
