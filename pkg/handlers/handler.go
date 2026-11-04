package handlers

import (
	"net/http"
	"time"

	"github.com/app/monorepo/services/auth/pkg/store"
	"github.com/app/monorepo/services/auth/pkg/tokens"
)

const (
	SessionCookie = "auth_session"
	stateCookie   = "oauth_state"
	clientCookie  = "oauth_client"

	HeaderUserID    = "X-User-Id"
	HeaderUserEmail = "X-User-Email"

	maxBodyBytes = 1 << 20
)

type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	GoogleAuthURL      string
	GoogleTokenURL     string
	GoogleUserInfoURL  string

	FrontendURL    string
	AllowedOrigins []string
	CookieSecure   bool
	SessionTTL     time.Duration
	HTTPClient     *http.Client
}

type Handler struct {
	jwt   *tokens.JWTManager
	users store.Store
	cfg   Config
}

func New(jwtMgr *tokens.JWTManager, users store.Store, cfg Config) *Handler {
	if cfg.GoogleAuthURL == "" {
		cfg.GoogleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	if cfg.GoogleTokenURL == "" {
		cfg.GoogleTokenURL = "https://oauth2.googleapis.com/token"
	}
	if cfg.GoogleUserInfoURL == "" {
		cfg.GoogleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	}
	if cfg.GoogleRedirectURL == "" {
		cfg.GoogleRedirectURL = "http://localhost:8080/auth/google-callback"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Handler{jwt: jwtMgr, users: users, cfg: cfg}
}
