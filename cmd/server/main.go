package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/app/monorepo/services/auth/pkg/handlers"
	"github.com/app/monorepo/services/auth/pkg/store"
	"github.com/app/monorepo/services/auth/pkg/tokens"
	"github.com/joho/godotenv"
)

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	// 1. Muat file .env secara otomatis (jika ada) saat development
	if err := godotenv.Load(); err != nil {
		_ = godotenv.Load("../../.env")
		log.Println("Info: File .env tidak ditemukan, membaca dari OS environment variables")
	}

	env := getenv("ENV", "development")
	production := env == "production"

	// 2. Validasi & Fallback JWT_SECRET
	jwtKey := os.Getenv("JWT_SECRET")
	if production && len(jwtKey) < 32 {
		log.Fatal("JWT_SECRET wajib diisi (minimal 32 karakter) saat ENV=production")
	}
	if jwtKey == "" {
		jwtKey = "dev-only-secret-do-not-use-in-production!"
		log.Println("PERINGATAN: JWT_SECRET kosong, memakai kunci pengembangan")
	}

	// 3. Konfigurasi Security Cookie
	cookieSecure := production
	if v := strings.TrimSpace(os.Getenv("COOKIE_SECURE")); v != "" {
		cookieSecure = v == "true" || v == "1"
	}

	// 4. Formatting CORS Origins tanpa duplikasi
	frontend := strings.TrimRight(os.Getenv("FRONTEND_URL"), "/")
	originMap := make(map[string]bool)

	// Tambahkan default localhost untuk kebutuhan lokal UI dev
	originMap["http://localhost:3000"] = true

	if frontend != "" {
		originMap[frontend] = true
	}

	for _, o := range strings.Split(getenv("CORS_ORIGINS", ""), ",") {
		if o = strings.TrimSpace(o); o != "" {
			originMap[strings.TrimRight(o, "/")] = true
		}
	}

	origins := make([]string, 0, len(originMap))
	for o := range originMap {
		origins = append(origins, o)
	}

	// 5. Database wajib: auth tidak boleh berjalan tanpa penyimpanan permanen.
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		log.Fatal("DATABASE_URL wajib diisi: layanan auth tidak berjalan tanpa database")
	}
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 60*time.Second)
	users, err := store.OpenPostgres(dbCtx, dsn)
	dbCancel()
	if err != nil {
		log.Fatalf("Gagal menyiapkan database: %v", err)
	}
	defer users.Close()
	log.Println("Database terhubung, skema auth siap")

	// 6. Inisialisasi Handler & Dependencies
	h := handlers.New(
		tokens.NewJWTManager(jwtKey, 24*time.Hour),
		users,
		handlers.Config{
			GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			GoogleRedirectURL:  getenv("GOOGLE_REDIRECT_URL", "http://localhost:8080/auth/google-callback"),
			FrontendURL:        frontend,
			AllowedOrigins:     origins,
			CookieSecure:       cookieSecure,
			SessionTTL:         24 * time.Hour,
		},
	)

	// 7. Konfigurasi Server HTTP
	addr := ":" + getenv("AUTH_PORT", "8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 8. Jalankan Server di Goroutine terpisah
	go func() {
		log.Printf("Auth service listening on %s (env=%s)", addr, env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server HTTP crash: %v", err)
		}
	}()

	// 9. Graceful Shutdown listener (menunggu sinyal SIGINT / SIGTERM dari OS/Docker)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down auth service gracefully...")

	// Beri waktu 10 detik untuk menyelesaikan in-flight HTTP requests
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server dipaksa berhenti: %v", err)
	}

	log.Println("Auth service berhenti dengan aman.")
}
