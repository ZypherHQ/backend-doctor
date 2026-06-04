package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
	"google.golang.org/grpc"
)

func main() {
	_ = chi.NewRouter()
	_ = fiber.New()
	_ = echo.New()
	_ = grpc.NewServer()
}
