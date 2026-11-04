package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/app/monorepo/services/auth/pkg/store"
	"github.com/app/monorepo/services/auth/pkg/tokens"
)

type settingsEnv struct {
	h     http.Handler
	users *store.MemoryStore
	token string
}

// newSettingsEnv mendaftar dan login (mobile) satu pengguna, lalu mengembalikan token Bearer-nya.
func newSettingsEnv(t *testing.T) *settingsEnv {
	t.Helper()
	users := store.NewMemory()
	h := New(tokens.NewJWTManager(secret, time.Hour), users, Config{AllowedOrigins: []string{"http://localhost:3000"}}).Routes()
	register(t, h)
	rec := do(h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"rahasia-123","client":"mobile"}`, nil)
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("login mobile gagal: %d %s", rec.Code, rec.Body)
	}
	return &settingsEnv{h: h, users: users, token: out.Token}
}

func (e *settingsEnv) call(method, path, body string) *httptest.ResponseRecorder {
	return do(e.h, method, path, body, map[string]string{"Authorization": "Bearer " + e.token, "Content-Type": "application/json"})
}

func (e *settingsEnv) user(t *testing.T, email string) *store.User {
	t.Helper()
	u, err := e.users.FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func message(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var r AuthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("respons bukan JSON: %v: %s", err, rec.Body)
	}
	return r.Message
}

func TestSettingsRequireAuth(t *testing.T) {
	e := newSettingsEnv(t)
	for _, c := range []struct{ method, path string }{
		{"PUT", "/settings/profile"}, {"POST", "/settings/change-password"}, {"DELETE", "/settings/delete-account"},
	} {
		rec := do(e.h, c.method, c.path, `{"name":"x"}`, nil)
		if rec.Code != 401 || message(t, rec) != "Unauthorized" {
			t.Fatalf("%s %s tanpa token = %d %s, harus 401 Unauthorized", c.method, c.path, rec.Code, rec.Body)
		}
	}
}

func TestSettingsRejectWrongMethod(t *testing.T) {
	e := newSettingsEnv(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/settings/profile"}, {"POST", "/settings/profile"}, {"GET", "/settings/change-password"}, {"GET", "/settings/delete-account"},
	} {
		if rec := e.call(c.method, c.path, `{}`); rec.Code != 405 {
			t.Fatalf("%s %s = %d, harus 405", c.method, c.path, rec.Code)
		}
	}
}

func TestUpdateProfileSavesAndReturnsUser(t *testing.T) {
	e := newSettingsEnv(t)
	rec := e.call("PUT", "/settings/profile",
		`{"name":"Tri Wahyu","userName":"ghofur_01","phoneNumber":" +62 812-3456 ","bio":"Akuntan","avatarUrl":"https://aumo.test/api/avatars/a.png"}`)
	if rec.Code != 200 || message(t, rec) != "Profil berhasil diperbarui" {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"userName":"ghofur_01"`) {
		t.Fatalf("respons harus memuat data pengguna: %s", rec.Body)
	}
	u := e.user(t, "ghofur@example.com")
	if u.Name != "Tri Wahyu" || u.UserName != "ghofur_01" || u.PhoneNumber != "+62 812-3456" || u.Bio != "Akuntan" ||
		u.AvatarURL != "https://aumo.test/api/avatars/a.png" {
		t.Fatalf("profil tidak tersimpan: %+v", u)
	}
}

func TestUpdateProfilePartialKeepsOtherFields(t *testing.T) {
	e := newSettingsEnv(t)
	e.call("PUT", "/settings/profile", `{"name":"Tri Wahyu","phoneNumber":"+6281234","bio":"Akuntan","avatarUrl":"https://a.test/x.png"}`)

	// PATCH hanya nama: telepon, bio, dan avatar tidak boleh terhapus.
	if rec := e.call("PATCH", "/settings/profile", `{"name":"Nama Baru"}`); rec.Code != 200 {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	u := e.user(t, "ghofur@example.com")
	if u.Name != "Nama Baru" || u.PhoneNumber != "+6281234" || u.Bio != "Akuntan" || u.AvatarURL != "https://a.test/x.png" {
		t.Fatalf("kolom lain harus tetap: %+v", u)
	}

	// Mengirim string kosong secara eksplisit menghapus telepon dan bio.
	if rec := e.call("PUT", "/settings/profile", `{"phoneNumber":"","bio":""}`); rec.Code != 200 {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	if u := e.user(t, "ghofur@example.com"); u.PhoneNumber != "" || u.Bio != "" || u.Name != "Nama Baru" {
		t.Fatalf("telepon dan bio harus terhapus, nama tetap: %+v", u)
	}
}

func TestUpdateProfileEmptyUserNameIsNotStored(t *testing.T) {
	e := newSettingsEnv(t)
	if _, err := e.users.Create(context.Background(), "Budi", "budi@example.com", "h"); err != nil {
		t.Fatal(err)
	}
	budi := tokenFor(t, e, "budi@example.com")
	// Username kosong dari dua pengguna tidak boleh saling bentrok.
	for _, tok := range []string{e.token, budi} {
		rec := do(e.h, "PUT", "/settings/profile", `{"userName":"  "}`, map[string]string{"Authorization": "Bearer " + tok})
		if rec.Code != 200 {
			t.Fatalf("username kosong = %d: %s", rec.Code, rec.Body)
		}
	}
	if u := e.user(t, "ghofur@example.com"); u.UserName != "" {
		t.Fatalf("username kosong tidak boleh tersimpan: %q", u.UserName)
	}
}

func tokenFor(t *testing.T, e *settingsEnv, email string) string {
	t.Helper()
	u := e.user(t, email)
	tok, err := tokens.NewJWTManager(secret, time.Hour).GenerateToken(u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestUpdateProfileValidation(t *testing.T) {
	e := newSettingsEnv(t)
	cases := []struct{ name, body, want string }{
		{"nama terlalu pendek", `{"name":"a"}`, "Nama minimal 2 karakter"},
		{"nama terlalu panjang", `{"name":"` + strings.Repeat("a", 101) + `"}`, "Nama maksimal 100 karakter"},
		{"username karakter tidak valid", `{"userName":"nama salah!"}`, "Username hanya boleh berisi huruf, angka, dan karakter - . _ @ +"},
		{"username terlalu panjang", `{"userName":"` + strings.Repeat("a", 257) + `"}`, "Username maksimal 256 karakter"},
		{"telepon tidak valid", `{"phoneNumber":"abc"}`, "Format nomor telepon tidak valid"},
		{"bio terlalu panjang", `{"bio":"` + strings.Repeat("a", 501) + `"}`, "Bio maksimal 500 karakter"},
		{"avatar bukan URL", `{"avatarUrl":"bukan-url"}`, "URL avatar harus berupa alamat http atau https yang valid"},
		{"avatar skema berbahaya", `{"avatarUrl":"javascript:alert(1)"}`, "URL avatar harus berupa alamat http atau https yang valid"},
		{"avatar data URI", `{"avatarUrl":"data:text/html;base64,PHNjcmlwdD4="}`, "URL avatar harus berupa alamat http atau https yang valid"},
		{"avatar tanpa host", `{"avatarUrl":"https://"}`, "URL avatar harus berupa alamat http atau https yang valid"},
		{"avatar terlalu panjang", `{"avatarUrl":"https://a.test/` + strings.Repeat("a", 2048) + `"}`, "URL avatar terlalu panjang"},
	}
	for _, c := range cases {
		rec := e.call("PUT", "/settings/profile", c.body)
		if rec.Code != 400 || message(t, rec) != c.want {
			t.Errorf("%s: %d %q, harus 400 %q", c.name, rec.Code, message(t, rec), c.want)
		}
	}
	if rec := e.call("PUT", "/settings/profile", `bukan json`); rec.Code != 400 {
		t.Fatalf("JSON rusak harus 400, dapat %d", rec.Code)
	}
	if u := e.user(t, "ghofur@example.com"); u.AvatarURL != "" || u.Bio != "" {
		t.Fatalf("permintaan yang ditolak tidak boleh mengubah data: %+v", u)
	}
}

func TestUpdateProfileUserNameTaken(t *testing.T) {
	e := newSettingsEnv(t)
	if _, err := e.users.Create(context.Background(), "Budi", "budi@example.com", "h"); err != nil {
		t.Fatal(err)
	}
	budi := e.user(t, "budi@example.com")
	n := "Budi"
	if _, err := e.users.UpdateProfile(context.Background(), budi.ID, store.ProfileUpdate{UserName: &n}); err != nil {
		t.Fatal(err)
	}
	rec := e.call("PUT", "/settings/profile", `{"userName":"budi"}`)
	if rec.Code != 409 || message(t, rec) != "Username sudah dipakai" {
		t.Fatalf("username ganda (tanpa membedakan huruf) = %d %s", rec.Code, rec.Body)
	}
	// Mengirim ulang username sendiri bukan bentrok.
	e.call("PUT", "/settings/profile", `{"userName":"ghofur"}`)
	if rec := e.call("PUT", "/settings/profile", `{"userName":"ghofur"}`); rec.Code != 200 {
		t.Fatalf("username sendiri harus lolos: %d %s", rec.Code, rec.Body)
	}
}

func TestChangePassword(t *testing.T) {
	e := newSettingsEnv(t)
	cases := []struct {
		name, body, want string
		code             int
	}{
		{"sandi baru pendek", `{"old_password":"rahasia-123","new_password":"pendek"}`, "Kata sandi baru harus 8 sampai 128 karakter", 400},
		{"sandi baru terlalu panjang", `{"old_password":"rahasia-123","new_password":"` + strings.Repeat("a", 129) + `"}`, "Kata sandi baru harus 8 sampai 128 karakter", 400},
		{"sandi baru sama dengan lama", `{"old_password":"rahasia-123","new_password":"rahasia-123"}`, "Kata sandi baru harus berbeda dari kata sandi lama", 400},
		{"sandi lama salah", `{"old_password":"salah-salah","new_password":"baru-12345"}`, "Kata sandi lama tidak sesuai", 401},
		{"sandi lama kosong", `{"old_password":"","new_password":"baru-12345"}`, "Kata sandi lama tidak sesuai", 401},
		{"sandi lama terlalu panjang", `{"old_password":"` + strings.Repeat("a", 200) + `","new_password":"baru-12345"}`, "Kata sandi lama tidak sesuai", 401},
	}
	for _, c := range cases {
		rec := e.call("POST", "/settings/change-password", c.body)
		if rec.Code != c.code || message(t, rec) != c.want {
			t.Errorf("%s: %d %q, harus %d %q", c.name, rec.Code, message(t, rec), c.code, c.want)
		}
	}

	rec := e.call("POST", "/settings/change-password", `{"old_password":"rahasia-123","new_password":"baru-12345"}`)
	if rec.Code != 200 || message(t, rec) != "Kata sandi berhasil diubah" {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
	if rec := do(e.h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"rahasia-123"}`, nil); rec.Code != 401 {
		t.Fatalf("sandi lama harus ditolak, dapat %d", rec.Code)
	}
	if rec := do(e.h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"baru-12345"}`, nil); rec.Code != 200 {
		t.Fatalf("sandi baru harus berhasil, dapat %d", rec.Code)
	}
}

func TestChangePasswordRejectsAccountWithoutPassword(t *testing.T) {
	e := newSettingsEnv(t)
	if _, err := e.users.UpsertExternal(context.Background(), "Google User", "g@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := do(e.h, "POST", "/settings/change-password", `{"old_password":"apa-saja-1","new_password":"baru-12345"}`,
		map[string]string{"Authorization": "Bearer " + tokenFor(t, e, "g@example.com")})
	if rec.Code != 400 {
		t.Fatalf("akun Google tanpa sandi harus 400, dapat %d: %s", rec.Code, rec.Body)
	}
}

func TestDeleteAccountRequiresPassword(t *testing.T) {
	e := newSettingsEnv(t)
	for _, body := range []string{``, `{}`, `{"password":"salah-salah"}`, `{"password":"` + strings.Repeat("a", 200) + `"}`} {
		rec := e.call("DELETE", "/settings/delete-account", body)
		if rec.Code != 400 && rec.Code != 401 {
			t.Fatalf("body %q = %d, harus ditolak", body, rec.Code)
		}
		if _, err := e.users.FindByEmail(context.Background(), "ghofur@example.com"); err != nil {
			t.Fatalf("akun tidak boleh terhapus saat konfirmasi gagal (body %q)", body)
		}
	}
}

func TestDeleteAccount(t *testing.T) {
	e := newSettingsEnv(t)
	rec := e.call("DELETE", "/settings/delete-account", `{"password":"rahasia-123"}`)
	if rec.Code != 200 || message(t, rec) != "Akun berhasil dihapus" {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("cookie sesi harus dihapus")
	}
	if rec := do(e.h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"rahasia-123"}`, nil); rec.Code != 401 {
		t.Fatalf("login akun terhapus harus 401, dapat %d", rec.Code)
	}
	// Token lama masih sah secara kriptografis, tetapi akunnya sudah tidak ada.
	if rec := e.call("PUT", "/settings/profile", `{"bio":"x"}`); rec.Code != 404 {
		t.Fatalf("token akun terhapus harus 404, dapat %d", rec.Code)
	}
	if rec := e.call("DELETE", "/settings/delete-account", `{"password":"rahasia-123"}`); rec.Code != 404 {
		t.Fatalf("hapus ulang harus 404, dapat %d", rec.Code)
	}
}

func TestDeleteAccountWithoutPasswordForGoogleAccount(t *testing.T) {
	e := newSettingsEnv(t)
	if _, err := e.users.UpsertExternal(context.Background(), "Google User", "g@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := do(e.h, "DELETE", "/settings/delete-account", ``,
		map[string]string{"Authorization": "Bearer " + tokenFor(t, e, "g@example.com")})
	if rec.Code != 200 {
		t.Fatalf("akun Google tanpa sandi dapat dihapus dengan token saja: %d %s", rec.Code, rec.Body)
	}
}

func TestCORSAllowsSettingsMethods(t *testing.T) {
	e := newSettingsEnv(t)
	rec := do(e.h, "OPTIONS", "/settings/profile", "", map[string]string{"Origin": "http://localhost:3000"})
	got := rec.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		if !strings.Contains(got, m) {
			t.Fatalf("Allow-Methods = %q, harus memuat %s", got, m)
		}
	}
}

// Terhadap PostgreSQL nyata: indeks unik lower(user_name) membuat username "" milik dua pengguna
// saling bentrok bila string kosong sampai ke database. MemoryStore tidak punya indeks itu.
func TestUpdateProfileEmptyUserNameWithPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL tidak diset; tes Postgres dilewati")
	}
	ctx := context.Background()
	pg, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	jwt := tokens.NewJWTManager(secret, time.Hour)
	h := New(jwt, pg, Config{}).Routes()

	suffix := time.Now().UnixNano()
	var ids []string
	t.Cleanup(func() {
		for _, id := range ids {
			_ = pg.Delete(ctx, id)
		}
		_ = pg.Close()
	})
	for i, name := range []string{"Satu", "Dua"} {
		u, err := pg.Create(ctx, name, fmt.Sprintf("kosong-%d-%d@example.com", suffix, i), "hash")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
		tok, _ := jwt.GenerateToken(u.ID, u.Email)
		rec := do(h, "PUT", "/settings/profile", `{"userName":"   ","bio":"halo"}`, map[string]string{"Authorization": "Bearer " + tok})
		if rec.Code != 200 {
			t.Fatalf("pengguna %d: username kosong harus 200, dapat %d: %s", i+1, rec.Code, rec.Body)
		}
		got, _ := pg.FindByID(ctx, u.ID)
		if got.UserName != "" || got.Bio != "halo" {
			t.Fatalf("pengguna %d: %+v", i+1, got)
		}
	}
}
