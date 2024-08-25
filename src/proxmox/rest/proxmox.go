package rest

import (
	"log"

	"github.com/gin-gonic/gin"
)

func ProxmoxRoutes(proxmox *gin.RouterGroup) {
	h, err := NewHandler()
	if err != nil {
		log.Printf("Failed to create handler: %v", err)
		return
	}
	proxmox.POST("/nodes", h.NodeHandler)
	proxmox.POST("/vm", h.ProxmoxVMListHandler)
	proxmox.GET("/proxy", h.ProxyHandler)
	proxmox.POST("/network", h.NetworkInfoHandler)
	proxmox.POST("/storage", h.StorageInfoHandler)
}
