package handlers

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Aturan validasi endpoint settings (padanan validator sumber .NET).
const (
	maxNameLen       = 100
	maxUserNameLen   = 256
	maxBioLen        = 500
	maxAvatarURLLen  = 2048
	maxPasswordInput = 128
)

var (
	// Digit, spasi, +, -, titik, dan tanda kurung; 5-20 karakter.
	phoneRe = regexp.MustCompile(`^\+?[0-9\s\-().]{5,20}$`)
	// Karakter yang diizinkan ASP.NET Identity untuk UserName.
	userNameRe = regexp.MustCompile(`^[A-Za-z0-9\-._@+]+$`)
)

// validAbsoluteHTTPURL: hanya http(s) dengan host; menolak javascript:, data:, dan sejenisnya.
func validAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// validateProfileFields memeriksa kolom profil yang sudah di-trim. Kembalian: pesan galat atau "".
// Nilai nil berarti kolom tidak dikirim dan dilewati.
func validateProfileFields(name, userName, phone, bio, avatar *string) string {
	if name != nil && utf8.RuneCountInString(*name) > maxNameLen {
		return "Nama maksimal 100 karakter"
	}
	if userName != nil && *userName != "" {
		if utf8.RuneCountInString(*userName) > maxUserNameLen {
			return "Username maksimal 256 karakter"
		}
		if !userNameRe.MatchString(*userName) {
			return "Username hanya boleh berisi huruf, angka, dan karakter - . _ @ +"
		}
	}
	if phone != nil && *phone != "" && !phoneRe.MatchString(*phone) {
		return "Format nomor telepon tidak valid"
	}
	if bio != nil && utf8.RuneCountInString(*bio) > maxBioLen {
		return "Bio maksimal 500 karakter"
	}
	if avatar != nil && *avatar != "" {
		if len(*avatar) > maxAvatarURLLen {
			return "URL avatar terlalu panjang"
		}
		if !validAbsoluteHTTPURL(*avatar) {
			return "URL avatar harus berupa alamat http atau https yang valid"
		}
	}
	return ""
}

func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	return &t
}
