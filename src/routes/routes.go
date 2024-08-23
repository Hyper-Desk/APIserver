package routes

import (
	proxmox_rest "hyperdesk/proxmox/rest"
	user_rest "hyperdesk/user/rest"
	vm_rest "hyperdesk/vm/rest"

	"github.com/gin-gonic/gin"
)

func Run(address string) error {
	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "https://hyperdesk.minboy.duckdns.org")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		c.Next()
	})

	router.OPTIONS("/*wildcard", func(c *gin.Context) {
		c.Status(200)
	})

	v1 := router.Group("/api/user")
	user_rest.UserRoutes(v1)

	v2 := router.Group("/api/vm")
	vm_rest.VmRoutes(v2)

	v3 := router.Group("/api/proxmox")
	proxmox_rest.ProxmoxRoutes(v3)

	return router.Run(address)
}
