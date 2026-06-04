package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	DB *sql.DB
}

func (h Handler) User(c *gin.Context) {
	ctx := context.Background()
	rows, err := h.DB.Query("select id from users where id=" + c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	_ = ctx
	_ = rows
}
