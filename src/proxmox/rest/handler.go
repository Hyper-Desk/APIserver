package rest

import (
	"log"
	"net/http"
	"os"
	"time"

	proxmoxdb "hyperdesk/proxmox/dblayer"
	"hyperdesk/proxmox/models"
	vmdb "hyperdesk/vm/dblayer"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
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

// TokenHandler는 Proxmox 인증 토큰을 생성합니다.
// @Summary Proxmox 인증 토큰 생성
// @Description Proxmox 인증 토큰을 생성합니다.
// @Tags proxmox
// @Accept json
// @Produce json
// @Param ProxmoxCredentials body models.ProxmoxCredentials true "Proxmox Credentials"
// @Success 200 {object} string "토큰 생성 성공 메시지"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/token [post]
// @Security ApiKey
func (h *Handler) TokenHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

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

	token, csrfToken, err := getProxmoxToken(creds)

	if err != nil {
		log.Printf("Failed to get Proxmox token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Proxmox 인증 실패했습니다."})
		return
	}

	c.SetCookie(
		"token",                         // 쿠키 이름
		token,                           // 쿠키 값
		int(time.Hour*24*7/time.Second), // 쿠키 만료 시간 (7일)
		"/",                             // 쿠키 유효 경로
		"",                              // 도메인 (기본적으로 현재 도메인)
		true,                            // HTTPS 사용 여부 (true로 설정하면 HTTPS에서만 전송)
		true,                            // HttpOnly 설정 (true로 설정하면 JavaScript에서 접근 불가)
	)

	c.SetCookie(
		"csrfToken",                     // 쿠키 이름
		csrfToken,                       // 쿠키 값
		int(time.Hour*24*7/time.Second), // 쿠키 만료 시간 (7일)
		"/",                             // 쿠키 유효 경로
		"",                              // 도메인 (기본적으로 현재 도메인)
		true,                            // HTTPS 사용 여부 (true로 설정하면 HTTPS에서만 전송)
		true,                            // HttpOnly 설정 (true로 설정하면 JavaScript에서 접근 불가)
	)

	c.JSON(http.StatusOK, gin.H{"message": "토큰이 성공적으로 생성되었습니다."})
}

// NodeHandler는 Proxmox에서 Node 리스트를 가져옵니다.
// @Summary Proxmox Node 리스트 가져오기
// @Description Proxmox에서 Node 리스트를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Success 200 {array} []string "Node 리스트"
// @Failure 401 {object} string "잘못된 토큰입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/nodes [get]
// @Security ApiKey
func (h *Handler) NodeHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)
	token, _ := getProxmoxTokenFromCookies(c)

	nodes, err := fetchProxmoxNodes(token, *proxy)
	if err != nil {
		return
	}

	c.JSON(http.StatusOK, nodes)
}

// ProxmoxVMListHandler는 Proxmox Node의 VM 리스트를 가져옵니다.
// @Summary Proxmox VM 리스트 가져오기
// @Description Proxmox Node의 VM 리스트를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Success 200 {array} map[string]interface{} "VM 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 401 {object} string "잘못된 토큰입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/vm [get]
// @Security ApiKey
func (h *Handler) ProxmoxVMListHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)
	token, _ := getProxmoxTokenFromCookies(c)

	_, err = h.proxmoxdbLayer.InsertProxy(*proxy)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "프록시 정보 저장 실패"})
		return
	}

	// Proxmox API를 통해 VM/CT 정보 가져오기
	vmInfo, err := fetchVMs(token, userId, *proxy, h)
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
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)

	c.JSON(http.StatusOK, proxy)
}

// NetworkInfoHandler는 Proxmox Node의 Network 리스트를 가져옵니다.
// @Summary Proxmox Network 리스트 가져오기
// @Description Proxmox Node의 Network 리스트를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Param node query string true "Node 이름"
// @Success 200 {array} []string "Network 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/network [get]
// @Security ApiKey
func (h *Handler) NetworkInfoHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)
	token, _ := getProxmoxTokenFromCookies(c)

	node := c.Query("node")
	if node == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node 파라미터가 필요합니다."})
		return
	}

	netData, err := fetchNetworks(node, token, *proxy)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", node, err)
		return
	}

	c.JSON(http.StatusOK, netData)
}

// StorageInfoHandler는 Proxmox Node의 Storage 리스트를 가져옵니다.
// @Summary Proxmox Storage 리스트 가져오기
// @Description Proxmox Node의 Storage 리스트를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Param node query string true "Node 이름"
// @Success 200 {array} models.StorageList "Storage 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/storage [get]
// @Security ApiKey
func (h *Handler) StorageInfoHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)
	token, _ := getProxmoxTokenFromCookies(c)

	node := c.Query("node")
	if node == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node 파라미터가 필요합니다."})
		return
	}

	storageData, err := fetchStorage(node, token, *proxy)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", node, err)
		return
	}

	c.JSON(http.StatusOK, storageData)
}

// IsoInfoHandler는 Proxmox Node의 ISO 이미지를 가져옵니다.
// @Summary Proxmox ISO 이미지 리스트 가져오기
// @Description Proxmox Node의 ISO 이미지 리스트를 가져옵니다.
// @Tags proxmox
// @Produce  json
// @Param node query string true "Node 이름"
// @Success 200 {array} []string "ISO 이미지 리스트"
// @Failure 400 {object} string "잘못된 요청입니다."
// @Failure 500 {object} string "서버 오류입니다."
// @Router /api/proxmox/iso [get]
// @Security ApiKey
func (h *Handler) IsoInfoHandler(c *gin.Context) {
	userId, err := h.validateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	proxy, _ := h.getProxy(userId)
	token, _ := getProxmoxTokenFromCookies(c)

	node := c.Query("node")
	if node == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node 파라미터가 필요합니다."})
		return
	}

	isoData, err := fetchIsos(node, token, *proxy)
	if err != nil {
		log.Printf("Failed to fetch data for node %s: %v", node, err)
		return
	}

	c.JSON(http.StatusOK, isoData)
}
