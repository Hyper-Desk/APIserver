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
	proxmox.POST("/token", h.TokenHandler)
	proxmox.GET("/nodes", h.NodeHandler)
	proxmox.GET("/vm", h.ProxmoxVMListHandler)
	proxmox.GET("/proxy", h.ProxyHandler)
	proxmox.GET("/network", h.NetworkInfoHandler)
	proxmox.GET("/storage", h.StorageInfoHandler)
	proxmox.GET("/iso", h.IsoInfoHandler)
}
