package rest

import (
	"log"

	"github.com/gin-gonic/gin"
)

func VmRoutes(vm *gin.RouterGroup) {
	h, err := NewHandler()

	if err != nil {
		log.Printf("Failed to create handler: %v", err)
		return
	}

	vm.GET("/vms", h.GetVMPoolHandler)
	vm.POST("/rent", h.RentVMHandler)
	vm.POST("/register", h.RegisterVMHandler)
}
