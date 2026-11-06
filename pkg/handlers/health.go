package handlers

import (
	"github.com/gofiber/fiber/v3"
)

// HealthCheck mengembalikan status kesehatan aplikasi dalam format JSON
func HealthCheck(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "ok",
		"service": "auth",
	})
}

// RegisterHealthRoutes me-register endpoint health di router Fiber
func RegisterHealthRoutes(app fiber.Router) {
	app.Get("/health", HealthCheck)
}
