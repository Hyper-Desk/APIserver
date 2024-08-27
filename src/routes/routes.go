package routes

import (
	proxmox_rest "hyperdesk/proxmox/rest"
	user_rest "hyperdesk/user/rest"
	vm_rest "hyperdesk/vm/rest"
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Swagger Hyperdesk API
// @version 1.0
// @description This is hyperdesk server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @Path api
// @securityDefinitions.Apikey ApiKey
// @in header
// @name Authorization

// swagger API 선언
func setupSwagger(r *gin.Engine) {
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/swagger/index.html")
	})

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}

func Run(address string) error {
	router := gin.Default()

	setupSwagger(router)

	v1 := router.Group("/api/user")
	user_rest.UserRoutes(v1)

	v2 := router.Group("/api/vm")
	vm_rest.VmRoutes(v2)

	v3 := router.Group("/api/proxmox")
	proxmox_rest.ProxmoxRoutes(v3)

	return router.Run(address)
}
