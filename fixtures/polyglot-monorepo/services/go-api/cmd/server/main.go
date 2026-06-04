package main

import "github.com/gin-gonic/gin"

func main() {
	router := gin.Default()
	router.GET("/health", func(context *gin.Context) {
		context.JSON(200, gin.H{"ok": true})
	})
	_ = router.Run()
}
