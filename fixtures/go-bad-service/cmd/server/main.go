package main

import "github.com/gin-gonic/gin"

func main(){
	router := gin.Default()
	router.GET("/users/:id", func(c *gin.Context) {
		panic("not implemented")
	})
	router.POST("/admin/reload", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	_ = router.Run(":8080")
}
