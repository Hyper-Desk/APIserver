package rest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"hyperdesk/proxmox/dblayer"
	"hyperdesk/proxmox/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	dbLayer dblayer.DBLayer
	jwtKey  []byte
}

// NewHandler는 새로운 핸들러를 생성합니다.
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

// ProxmoxVMListHandler는 Proxmox에서 VM 리스트를 가져옵니다.
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

	_, err = h.dbLayer.InsertProxy(proxy)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "프록시 정보 저장 실패"})
		return
	}

	vmInfo, err := fetchProxmoxData(creds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxmox VM 정보 가져오기 실패"})
		return
	}

	c.JSON(http.StatusOK, vmInfo)
}

// fetchProxmoxData fetches all VM and CT information from Proxmox.
func fetchProxmoxData(creds models.ProxmoxCredentials) (map[string]interface{}, error) {
	nodes, err := fetchProxmoxNodes(creds)
	if err != nil {
		return nil, err
	}

	allData := make(map[string]interface{})
	for _, node := range nodes {
		nodeData, err := fetchNodeVMsAndCTs(creds, node)
		if err != nil {
			log.Printf("Failed to fetch data for node %s: %v", node, err)
			continue
		}
		allData[node] = nodeData
	}

	return allData, nil
}

// fetchProxmoxNodes fetches the list of nodes from Proxmox.
func fetchProxmoxNodes(creds models.ProxmoxCredentials) ([]string, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/", creds.Address, creds.Port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	token, csrfToken, err := getProxmoxToken(creds)
	if err != nil {
		log.Printf("Failed to get Proxmox token: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "PVEAuthCookie="+token)
	if csrfToken != "" {
		req.Header.Set("CSRFPreventionToken", csrfToken)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	nodesData, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for nodes data")
	}

	var nodes []string
	for _, node := range nodesData {
		nodeMap, ok := node.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected format for node data")
		}
		nodeName, ok := nodeMap["node"].(string)
		if !ok {
			return nil, fmt.Errorf("unexpected format for node name")
		}
		nodes = append(nodes, nodeName)
	}

	return nodes, nil
}

// fetchNodeVMsAndCTs fetches VM and CT information for a given node.
func fetchNodeVMsAndCTs(creds models.ProxmoxCredentials, node string) (map[string]interface{}, error) {
	vmURL := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/qemu", creds.Address, creds.Port, node)
	ctURL := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/lxc", creds.Address, creds.Port, node)

	vmData, err := fetchProxmoxDataForURL(creds, vmURL)
	if err != nil {
		return nil, err
	}

	ctData, err := fetchProxmoxDataForURL(creds, ctURL)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"vms": vmData,
		"cts": ctData,
	}, nil
}

// fetchProxmoxDataForURL fetches data from a specific URL.
func fetchProxmoxDataForURL(creds models.ProxmoxCredentials, url string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	token, csrfToken, err := getProxmoxToken(creds)
	if err != nil {
		log.Printf("Failed to get Proxmox token: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "PVEAuthCookie="+token)
	if csrfToken != "" {
		req.Header.Set("CSRFPreventionToken", csrfToken)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for data")
	}

	return data, nil
}

func getProxmoxToken(creds models.ProxmoxCredentials) (string, string, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/access/ticket", creds.Address, creds.Port)
	data := fmt.Sprintf("username=%s&password=%s", creds.UserId+"@pam", creds.Password)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var result struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}

	token := result.Data.Ticket
	csrfToken := result.Data.CSRFPreventionToken

	return token, csrfToken, nil
}

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
	err = h.dbLayer.FindProxyByUserId(ctx, claims.UserId, &result)
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
