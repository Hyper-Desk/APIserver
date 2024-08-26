package rest

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	proxmoxdb "hyperdesk/proxmox/dblayer"
	"hyperdesk/proxmox/models"
	vmdb "hyperdesk/vm/dblayer"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	proxmoxdbLayer proxmoxdb.DBLayer
	vmdbLayer      vmdb.DBLayer
	jwtKey         []byte
}

// NewHandler는 새로운 핸들러를 생성합니다.
func NewHandler() (*Handler, error) {
	proxmoxdbLayer, err := proxmoxdb.NewORM()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create a new proxmox ORM", 1)
	}

	vmdbLayer, err := vmdb.NewORM()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create a new vm ORM", 1)
	}

	jwtKey := []byte(os.Getenv("TOKEN_SECRET"))

	return &Handler{
		proxmoxdbLayer: proxmoxdbLayer,
		vmdbLayer:      vmdbLayer,
		jwtKey:         jwtKey,
	}, nil
}

// NodeHandler는 Proxmox에서 Node 리스트를 가져옵니다.
// @Summary Proxmox Node 리스트 가져오기
// @Description Proxmox에서 Node 리스트를 가져옵니다.
// @Tags proxmox
// @Accept  json
// @Produce  json
// @Param  ProxmoxCredentials  body  models.ProxmoxCredentials  true  "Proxmox Credentials"
// @Success 200 {array} []string "Node 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/nodes [post]
func (h *Handler) NodeHandler(c *gin.Context) {
	var creds models.ProxmoxCredentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	nodes, err := fetchProxmoxNodes(creds)
	if err != nil {
		return
	}

	c.JSON(http.StatusOK, nodes)
}

// ProxmoxVMListHandler는 Proxmox Node의 VM 리스트를 가져옵니다.
// @Summary Proxmox VM 리스트 가져오기
// @Description Proxmox Node의 VM 리스트를 가져옵니다.
// @Tags proxmox
// @Accept  json
// @Produce  json
// @Param  ProxmoxCredentials  body  models.ProxmoxCredentials  true  "Proxmox Credentials"
// @Success 200 {array} map[string]interface{} "VM 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 401 {object} string "잘못된 토큰입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/vm [post]
// @Security ApiKey
func (h *Handler) ProxmoxVMListHandler(c *gin.Context) {
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 토큰입니다."})
		return
	}

	userId := claims.UserId

	var creds models.ProxmoxCredentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	proxy := models.Proxy{
		UserId:  userId,
		Address: creds.Address,
		Port:    creds.Port,
	}

	_, err = h.proxmoxdbLayer.InsertProxy(proxy)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "프록시 정보 저장 실패"})
		return
	}

	// Proxmox API를 통해 VM/CT 정보 가져오기
	vmInfo, err := fetchVMs(creds, userId, h)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxmox VM 정보 가져오기 실패"})
		return
	}

	c.JSON(http.StatusOK, vmInfo)
}

// ProxyHandler는 Proxmox 서버의 url, port 정보를 가져옵니다.
// @Summary Proxmox 서버의 프록시 정보 가져오기
// @Description Proxmox 서버의 URL 및 포트 정보를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Success 200 {object} models.Proxy "프록시 정보"
// @Failure 401 {object} string "잘못된 토큰입니다."
// @Failure 404 {object} string "프록시 정보를 찾을 수 없습니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/proxy [get]
// @Security ApiKey
func (h *Handler) ProxyHandler(c *gin.Context) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result models.Proxy
	err = h.proxmoxdbLayer.FindProxyByUserId(ctx, claims.UserId, &result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "프록시 정보를 찾을 수 없습니다."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// NetworkInfoHandler Proxmox Node의 Network 리스트를 가져옵니다.
// @Summary Proxmox Network 리스트 가져오기
// @Description Proxmox Node의 Network 리스트를 가져옵니다.
// @Tags proxmox
// @Accept  json
// @Produce  json
// @Param ProxmoxRequestBody body models.ProxmoxRequestBody true "Proxmox Request Body"
// @Success 200 {array} []string "Network 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/network [post]
func (h *Handler) NetworkInfoHandler(c *gin.Context) {
	var req models.ProxmoxRequestBody
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	netData, err := fetchNetworks(req)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", req.Node, err)
		return
	}

	c.JSON(http.StatusOK, netData)
}

// StorageInfoHandler는 Proxmox Node의 Storage 리스트를 가져옵니다.
// @Summary Proxmox Storage 리스트 가져오기
// @Description Proxmox Node의 Storage 리스트를 가져옵니다.
// @Tags proxmox
// @Accept  json
// @Produce  json
// @Param ProxmoxRequestBody body models.ProxmoxRequestBody true "Proxmox Request Body"
// @Success 200 {array} models.StorageList "Storage 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/storage [post]
func (h *Handler) StorageInfoHandler(c *gin.Context) {
	var req models.ProxmoxRequestBody
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	storageData, err := fetchStorage(req)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", req.Node, err)
		return
	}

	c.JSON(http.StatusOK, storageData)
}

func (h *Handler) IsoInfoHandler(c *gin.Context) {
	var req models.ProxmoxRequestBody
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	isoData, err := fetchIsos(req)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", req.Node, err)
		return
	}

	c.JSON(http.StatusOK, isoData)
}
