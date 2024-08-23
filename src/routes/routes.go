package routes

import (
	proxmox_rest "hyperdesk/proxmox/rest"
	user_rest "hyperdesk/user/rest"
	vm_rest "hyperdesk/vm/rest"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Run(address string) (chan error, error) {
	router := gin.Default()

	v1 := router.Group("/api/user")
	user_rest.UserRoutes(v1)

	v2 := router.Group("/api/vm")
	vm_rest.VmRoutes(v2)

	v3 := router.Group("/api/proxmox")
	proxmox_rest.ProxmoxRoutes(v3)

	httpsErrChan := make(chan error)
	go func() { httpsErrChan <- http.ListenAndServeTLS(address, "cert.pem", "key.pem", router) }()

	return httpsErrChan, router.Run(address)
}
