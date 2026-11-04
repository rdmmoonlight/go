package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/app/monorepo/services/auth/pkg/store"
	"github.com/app/monorepo/services/auth/pkg/tokens"
)

const secret = "kunci-uji-minimal-32-karakter-aman!!"

func newHandler(cfg Config) *Handler {
	if cfg.AllowedOrigins == nil {
		cfg.AllowedOrigins = []string{"http://localhost:3000"}
	}
	return New(tokens.NewJWTManager(secret, time.Hour), store.NewMemory(), cfg)
}

func do(h http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func register(t *testing.T, h http.Handler) {
	t.Helper()
	rec := do(h, "POST", "/auth/register", `{"name":"Ghofur","email":"Ghofur@Example.com","password":"rahasia-123"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", rec.Code, rec.Body)
	}
}

func TestRegisterValidationAndDuplicate(t *testing.T) {
	h := newHandler(Config{}).Routes()
	register(t, h)
	if rec := do(h, "POST", "/auth/register", `{"name":"G","email":"x@y.z","password":"rahasia-123"}`, nil); rec.Code != 400 {
		t.Fatalf("nama pendek harus 400, dapat %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/register", `{"name":"Budi","email":"b@y.z","password":"pendek"}`, nil); rec.Code != 400 {
		t.Fatalf("sandi pendek harus 400, dapat %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/register", `{"name":"Dua","email":"ghofur@example.com","password":"rahasia-123"}`, nil); rec.Code != 409 {
		t.Fatalf("email ganda harus 409, dapat %d", rec.Code)
	}
}

func TestLoginRejectsUnknownAndWrongPassword(t *testing.T) {
	h := newHandler(Config{}).Routes()
	register(t, h)
	if rec := do(h, "POST", "/auth/login", `{"email":"tidak@ada.io","password":"rahasia-123"}`, nil); rec.Code != 401 {
		t.Fatalf("pengguna tak dikenal harus 401, dapat %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"salah-salah"}`, nil); rec.Code != 401 {
		t.Fatalf("sandi salah harus 401, dapat %d", rec.Code)
	}
}

func TestWebLoginSetsCookieAndValidateReturnsIdentityHeaders(t *testing.T) {
	h := newHandler(Config{CookieSecure: true}).Routes()
	register(t, h)
	rec := do(h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"rahasia-123","client":"web"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("cookie sesi harus HttpOnly dan Secure: %+v", cookie)
	}

	v := do(h, "GET", "/auth/validate", "", map[string]string{"Cookie": SessionCookie + "=" + cookie.Value})
	if v.Code != 200 {
		t.Fatalf("validate = %d", v.Code)
	}
	if v.Header().Get(HeaderUserID) == "" || v.Header().Get(HeaderUserEmail) != "ghofur@example.com" {
		t.Fatalf("header identitas tidak ada: %v", v.Header())
	}
	if do(h, "GET", "/auth/validate", "", nil).Code != 401 {
		t.Fatal("tanpa token harus 401")
	}
}

func TestMobileLoginReturnsTokenUsableAsBearer(t *testing.T) {
	h := newHandler(Config{}).Routes()
	register(t, h)
	rec := do(h, "POST", "/auth/login", `{"email":"ghofur@example.com","password":"rahasia-123","client":"mobile"}`, nil)
	var body AuthResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Token == "" {
		t.Fatalf("mobile harus menerima token: %s", rec.Body)
	}
	me := do(h, "GET", "/auth/me", "", map[string]string{"Authorization": "Bearer " + body.Token})
	if me.Code != 200 {
		t.Fatalf("me = %d", me.Code)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	h := newHandler(Config{}).Routes()
	rec := do(h, "POST", "/auth/logout", "", nil)
	if rec.Code != 200 {
		t.Fatalf("logout = %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 {
			return
		}
	}
	t.Fatal("cookie sesi harus dihapus")
}

func TestCORSAllowlist(t *testing.T) {
	h := newHandler(Config{}).Routes()
	ok := do(h, "OPTIONS", "/auth/login", "", map[string]string{"Origin": "http://localhost:3000"})
	if ok.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("origin yang diizinkan harus dipantulkan")
	}
	bad := do(h, "OPTIONS", "/auth/login", "", map[string]string{"Origin": "https://jahat.example"})
	if bad.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("origin asing tidak boleh diizinkan")
	}
}

func fakeGoogle(t *testing.T, verified bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "kode-sah" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-123"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-123" {
			http.Error(w, "unauth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "g-1", "email": "g@example.com", "verified_email": verified, "name": "Gee",
		})
	})
	return httptest.NewServer(mux)
}

func googleHandler(t *testing.T, g *httptest.Server, frontend string) http.Handler {
	return newHandler(Config{
		GoogleClientID: "cid", GoogleClientSecret: "csecret",
		GoogleAuthURL: g.URL + "/auth", GoogleTokenURL: g.URL + "/token", GoogleUserInfoURL: g.URL + "/userinfo",
		FrontendURL: frontend,
	}).Routes()
}

func TestGoogleFlowSuccessWebRedirect(t *testing.T) {
	g := fakeGoogle(t, true)
	defer g.Close()
	h := googleHandler(t, g, "https://front.example")

	start := do(h, "GET", "/auth/google-login", "", nil)
	if start.Code != http.StatusTemporaryRedirect {
		t.Fatalf("google-login = %d", start.Code)
	}
	loc, _ := url.Parse(start.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" || state == "random-csrf-state-token" {
		t.Fatalf("state harus acak, dapat %q", state)
	}
	cookies := ""
	for _, c := range start.Result().Cookies() {
		cookies += c.Name + "=" + c.Value + "; "
	}

	cb := do(h, "GET", "/auth/google-callback?code=kode-sah&state="+state, "", map[string]string{"Cookie": cookies})
	if cb.Code != http.StatusFound || cb.Header().Get("Location") != "https://front.example" {
		t.Fatalf("callback = %d loc=%s body=%s", cb.Code, cb.Header().Get("Location"), cb.Body)
	}
	hasSession := false
	for _, c := range cb.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatal("cookie sesi harus terpasang")
	}
}

func TestGoogleCallbackRejectsBadState(t *testing.T) {
	g := fakeGoogle(t, true)
	defer g.Close()
	h := googleHandler(t, g, "")
	if rec := do(h, "GET", "/auth/google-callback?code=kode-sah&state=palsu", "", nil); rec.Code != 400 {
		t.Fatalf("tanpa cookie state harus 400, dapat %d", rec.Code)
	}
	if rec := do(h, "GET", "/auth/google-callback?code=kode-sah&state=palsu", "", map[string]string{"Cookie": "oauth_state=lain"}); rec.Code != 400 {
		t.Fatalf("state tidak cocok harus 400, dapat %d", rec.Code)
	}
}

func TestGoogleRejectsUnverifiedEmailAndMobileGetsToken(t *testing.T) {
	g := fakeGoogle(t, false)
	h := googleHandler(t, g, "")
	rec := do(h, "GET", "/auth/google-callback?code=kode-sah&state=s", "", map[string]string{"Cookie": "oauth_state=s"})
	if rec.Code != 403 {
		t.Fatalf("email belum terverifikasi harus 403, dapat %d", rec.Code)
	}
	g.Close()

	g2 := fakeGoogle(t, true)
	defer g2.Close()
	h2 := googleHandler(t, g2, "")
	rec = do(h2, "GET", "/auth/google-callback?code=kode-sah&state=s", "", map[string]string{"Cookie": "oauth_state=s; oauth_client=mobile"})
	var body AuthResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body.Token == "" {
		t.Fatalf("mobile harus menerima token: %d %s", rec.Code, rec.Body)
	}
}

func TestGoogleDisabledWithoutCredentials(t *testing.T) {
	h := newHandler(Config{}).Routes()
	if rec := do(h, "GET", "/auth/google-login", "", nil); rec.Code != 503 {
		t.Fatalf("tanpa kredensial harus 503, dapat %d", rec.Code)
	}
}
