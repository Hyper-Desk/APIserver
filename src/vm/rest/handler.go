package rest

import (
	"hyperdesk/proxmox/rest"
	"hyperdesk/vm/dblayer"
	"hyperdesk/vm/models"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
)

type Handler struct {
	dbLayer dblayer.DBLayer
	jwtKey  []byte
}

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}

func NewHandler() (*Handler, error) {
	dbLayer, err := dblayer.NewORM()

	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create a new ORM", 1)
	}

	jwtKey := []byte(os.Getenv("TOKEN_SECRET"))

	return &Handler{
		dbLayer: dbLayer,
		jwtKey:  jwtKey,
	}, nil
}

// VM Pool을 가져오는 GET 요청 핸들러
func (h *Handler) GetVMPoolHandler(c *gin.Context) {
	vms, err := h.dbLayer.FindAvailableVMs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	c.JSON(http.StatusOK, vms)
}

// VM Pool에서 빌리는 POST 요청 핸들러
func (h *Handler) RentVMHandler(c *gin.Context) {
	var req struct {
		VMId   string `json:"vmId"`
		UserId string `json:"userId"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	vm, err := h.dbLayer.FindVMById(req.VMId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	if vm == nil || vm.Status != "available" {
		c.JSON(http.StatusNotFound, gin.H{"error": "사용 가능한 VM을 찾을 수 없습니다."})
		return
	}

	_, err = h.dbLayer.UpdateVMStatus(req.VMId, "rented", req.UserId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "VM rented successfully"})
}

// VM Pool에 빌려줄 VM을 등록하는 POST 요청 핸들러
func (h *Handler) RegisterVMHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "토큰이 제공되지 않았습니다."})
		return
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 토큰 형식입니다."})
		return
	}

	accessToken := authHeaderParts[1]
	claims := &models.TokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return h.jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 액세스 토큰입니다."})
		return
	}

	var vm models.VM
	if err := c.BindJSON(&vm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	// VM의 상태와 사용자 ID 설정
	vm.Status = "available"
	vm.UserId = claims.UserId

	// Unique ID 생성 및 할당
	vm.UniqueId = rest.GenerateUniqueId(vm.VMId, vm.Name, vm.UserId, vm.MaxDisk, vm.MaxMem, vm.CPU)

	_, err = h.dbLayer.InsertVM(vm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "VM registered successfully", "uniqueId": vm.UniqueId})
}
