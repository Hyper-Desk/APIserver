package rest

import (
	"log"

	"github.com/gin-gonic/gin"
)

func UserRoutes(r *gin.RouterGroup) {
	h, err := NewHandler()
	if err != nil {
		log.Printf("Failed to create handler: %v", err)
		return
	}

	r.POST("/signup", h.RegisterHandler)
	r.POST("/login", h.LoginHandler)
	r.GET("/refresh", h.RefreshHandler)
	// r.GET("/proxy", h.ProxyHandler)
}
