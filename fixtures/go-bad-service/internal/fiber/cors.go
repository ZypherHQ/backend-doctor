package fiberconfig

import "github.com/gofiber/fiber/v2/middleware/cors"

func CORS() cors.Config {
	return cors.Config{
		AllowOrigins: "*",
	}
}
