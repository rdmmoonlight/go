package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
)

func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.googleEnabled() {
		writeError(w, http.StatusServiceUnavailable, "Login Google belum dikonfigurasi")
		return
	}
	client := "web"
	if isMobile(r.URL.Query().Get("client")) {
		client = "mobile"
	}
	state := randomToken(16)
	http.SetCookie(w, h.shortCookie(stateCookie, state))
	http.SetCookie(w, h.shortCookie(clientCookie, client))

	q := url.Values{}
	q.Set("client_id", h.cfg.GoogleClientID)
	q.Set("redirect_uri", h.cfg.GoogleRedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("access_type", "offline")
	http.Redirect(w, r, h.cfg.GoogleAuthURL+"?"+q.Encode(), http.StatusTemporaryRedirect)
}

func (h *Handler) exchangeCode(code string) (string, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", h.cfg.GoogleClientID)
	form.Set("client_secret", h.cfg.GoogleClientSecret)
	form.Set("redirect_uri", h.cfg.GoogleRedirectURL)
	form.Set("grant_type", "authorization_code")

	resp, err := h.cfg.HTTPClient.PostForm(h.cfg.GoogleTokenURL, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Google menolak kode otorisasi")
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.AccessToken == "" {
		return "", errors.New("respons token Google tidak valid")
	}
	return body.AccessToken, nil
}

func (h *Handler) fetchGoogleUser(accessToken string) (*googleUser, error) {
	req, err := http.NewRequest(http.MethodGet, h.cfg.GoogleUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := h.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Google menolak permintaan profil")
	}
	var u googleUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.googleEnabled() {
		writeError(w, http.StatusServiceUnavailable, "Login Google belum dikonfigurasi")
		return
	}
	sc, err := r.Cookie(stateCookie)
	state := r.URL.Query().Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(sc.Value), []byte(state)) != 1 {
		writeError(w, http.StatusBadRequest, "Invalid OAuth state")
		return
	}
	client := "web"
	if cc, err := r.Cookie(clientCookie); err == nil && isMobile(cc.Value) {
		client = "mobile"
	}
	h.clearCookie(w, stateCookie)
	h.clearCookie(w, clientCookie)

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Kode otorisasi tidak ada")
		return
	}
	accessToken, err := h.exchangeCode(code)
	if err != nil {
		log.Printf("google exchange: %v", err)
		writeError(w, http.StatusBadGateway, "Gagal menukar kode dengan Google")
		return
	}
	gu, err := h.fetchGoogleUser(accessToken)
	if err != nil {
		log.Printf("google userinfo: %v", err)
		writeError(w, http.StatusBadGateway, "Gagal mengambil profil Google")
		return
	}
	if gu.Email == "" || !gu.VerifiedEmail {
		writeError(w, http.StatusForbidden, "Email Google belum terverifikasi")
		return
	}
	user, err := h.users.UpsertExternal(r.Context(), gu.Name, gu.Email)
	if err != nil {
		log.Printf("google upsert: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Layanan database tidak tersedia")
		return
	}
	tokenStr, err := h.jwt.GenerateToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate session token")
		return
	}
	if client == "web" {
		h.setSession(w, tokenStr)
		if h.cfg.FrontendURL != "" {
			http.Redirect(w, r, h.cfg.FrontendURL, http.StatusFound)
			return
		}
		writeJSON(w, http.StatusOK, AuthResponse{Message: "Google login successful", Data: user})
		return
	}
	writeJSON(w, http.StatusOK, AuthResponse{Message: "Google login successful", Token: tokenStr, Data: user})
}
