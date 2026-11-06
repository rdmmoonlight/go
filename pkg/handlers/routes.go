package handlers

import (
	_ "embed"

	"github.com/gofiber/fiber/v3"
)

//go:embed openapi.json
var openAPISpec []byte

// RegisterRoutes mendaftarkan seluruh endpoint aplikasi ke router Fiber v3
func (h *Handler) RegisterRoutes(app *fiber.App) {
	// Root endpoint
	app.Get("/", func(c fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"service": "auth-service",
			"status":  "ok",
		})
	})

	// OpenAPI Spec endpoint
	app.Get("/openapi.json", func(c fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "application/json; charset=utf-8")
		return c.Status(fiber.StatusOK).Send(openAPISpec)
	})

	// Health Check endpoints
	app.Get("/health", h.Health)
	app.Get("/healthz", h.Healthz)

	// Auth group endpoints
	auth := app.Group("/auth")
	auth.Post("/register", h.Register)
	auth.Post("/login", h.Login)
	auth.Post("/logout", h.Logout)
	auth.Get("/validate", h.Validate)
	auth.Get("/me", h.Me)
	auth.Get("/google-login", h.GoogleLogin)
	auth.Get("/google-callback", h.GoogleCallback)

	// Settings group endpoints
	settings := app.Group("/settings")
	settings.Put("/profile", h.UpdateProfile)
	settings.Post("/change-password", h.ChangePassword)
	settings.Delete("/delete-account", h.DeleteAccount)
}

// Health check handler untuk /health
func (h *Handler) Health(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"service": "auth-service",
		"status":  "ok",
	})
}
