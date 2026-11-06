package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/app/monorepo/services/auth/pkg/handlers"
	"github.com/app/monorepo/services/auth/pkg/store"
	"github.com/app/monorepo/services/auth/pkg/tokens"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/joho/godotenv"
)

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	// 1. Muat file .env secara otomatis
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

	// 5. Inisialisasi Database SQLite Lokal
	users, err := store.NewSQLiteStore("app.db")
	if err != nil {
		log.Fatalf("Gagal menyiapkan database SQLite: %v", err)
	}
	log.Println("Database SQLite terhubung (app.db)")

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

	// 7. Inisialisasi Aplikasi Fiber v3
	app := fiber.New(fiber.Config{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	})

	// 8. Middleware CORS (Harus dipasang sebelum registrasi rute)
	app.Use(cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowCredentials: true,
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	}))

	// 9. Registrasi Seluruh Rute dari Package Handlers
	h.RegisterRoutes(app)

	// 10. Jalankan Server di Goroutine Terpisah
	addr := ":" + getenv("AUTH_PORT", "8080")
	go func() {
		log.Printf("Server Fiber v3 listening on %s (env=%s)", addr, env)
		if err := app.Listen(addr); err != nil {
			log.Printf("Server HTTP closed: %v", err)
		}
	}()

	// 11. Graceful Shutdown Listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Server dipaksa berhenti: %v", err)
	}

	log.Println("Server berhenti dengan aman.")
}
