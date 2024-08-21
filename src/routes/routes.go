package routes

import (
	user_rest "hyperdesk/user/rest"
    proxmox_rest "hyperdesk/proxmox/rest"
    vm_rest "hyperdesk/vm/rest"
	"github.com/gin-gonic/gin"
)

func Run(address string) error {
	router := gin.Default()

	v1 := router.Group("/api/user")
	user_rest.UserRoutes(v1)

    v2 := router.Group("/api/vm")
	vm_rest.VmRoutes(v2)

    v3 := router.Group("/api/proxmox")
	proxmox_rest.ProxmoxRoutes(v3)

	return router.Run(address)
}
