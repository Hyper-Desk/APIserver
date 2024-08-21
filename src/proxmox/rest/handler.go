package rest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	"go.mongodb.org/mongo-driver/bson"
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

	_, err = h.proxmoxdbLayer.InsertProxy(proxy)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "프록시 정보 저장 실패"})
		return
	}

	// Proxmox API를 통해 VM/CT 정보 가져오기
	vmInfo, err := fetchProxmoxData(creds, userId, h)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxmox VM 정보 가져오기 실패"})
		return
	}

	c.JSON(http.StatusOK, vmInfo)
}

// fetchProxmoxData fetches all VM and CT information from Proxmox.
func fetchProxmoxData(creds models.ProxmoxCredentials, userId string, h *Handler) (map[string]interface{}, error) {
	nodes, err := fetchProxmoxNodes(creds)
	if err != nil {
		return nil, err
	}

	allData := make(map[string]interface{})
	for _, node := range nodes {
		nodeData, err := fetchNodeVMsAndCTs(creds, node, userId, h)
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
func fetchNodeVMsAndCTs(creds models.ProxmoxCredentials, node string, userId string, h *Handler) (map[string]interface{}, error) {
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

	processedVMs, vmUniqueIds := processVMData(vmData, userId, h)
	processedCTs, ctUniqueIds := processVMData(ctData, userId, h)

	allUniqueIds := append(vmUniqueIds, ctUniqueIds...)
	deleteAbsentsVMs(allUniqueIds, userId, h)

	allData := map[string]interface{}{
		"vms": processedVMs,
		"cts": processedCTs,
	}

	return allData, nil
}

// GenerateUniqueId generates a unique ID based on VM/CT properties.
func GenerateUniqueId(vmid, name, userid string, maxdisk string, maxmem string, cpu int) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%d", vmid, name, userid, maxdisk, maxmem, cpu)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// processVMData processes the VM/CT data and checks if it's already registered.
func processVMData(data interface{}, userId string, h *Handler) ([]interface{}, []string) {
	processed := []interface{}{}
	uniqueIds := []string{}

	// Assuming `data` is an array of VMs/CTs
	vms := data.([]interface{})

	for _, vm := range vms {
		vmMap := vm.(map[string]interface{})

		vmid := fmt.Sprintf("%v", vmMap["vmid"]) // Convert vmid to string if it's not
		name := vmMap["name"].(string)

		// 소수점 둘째 자리까지 표시
		diskread := fmt.Sprintf("%.2f", vmMap["diskread"].(float64)/(1024*1024*1024)) // GB
		vmMap["diskread"] = diskread

		diskwrite := fmt.Sprintf("%.2f", vmMap["diskwrite"].(float64)/(1024*1024*1024)) // GB
		vmMap["diskwrite"] = diskwrite

		disk := fmt.Sprintf("%.2f", vmMap["disk"].(float64)/(1024*1024*1024)) // GB
		vmMap["disk"] = disk

		maxdisk := fmt.Sprintf("%.2f", vmMap["maxdisk"].(float64)/(1024*1024*1024)) // GB
		vmMap["maxdisk"] = maxdisk

		maxmem := fmt.Sprintf("%.2f", vmMap["maxmem"].(float64)/(1024*1024*1024)) // GB
		vmMap["maxmem"] = maxmem

		mem := fmt.Sprintf("%.2f", vmMap["mem"].(float64)/(1024*1024*1024)) // GB
		vmMap["mem"] = mem

		cpu := int(vmMap["cpus"].(float64))
		vmMap["cpus"] = cpu

		uniqueId := GenerateUniqueId(vmid, name, userId, maxdisk, maxmem, cpu)
		vmMap["uniqueId"] = uniqueId

		// Add the uniqueId to the list
		uniqueIds = append(uniqueIds, uniqueId)

		// Check if this VM/CT is already registered
		_, err := h.vmdbLayer.FindVMByUniqueId(uniqueId)

		if err == mongo.ErrNoDocuments {
			// VM is not yet registered
			vmMap["registered"] = false
		} else if err == nil {
			// VM is already registered
			vmMap["registered"] = true
		} else {
			// Handle potential errors
			log.Printf("Error checking if VM is registered: %v", err)
		}

		processed = append(processed, vmMap)
	}

	return processed, uniqueIds
}

// deleteAbsentsVMs deletes VMs from the collection that are no longer present in the Proxmox API response.
func deleteAbsentsVMs(fetchedUniqueIds []string, userId string, h *Handler) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fetch all VMs for the userId
	cursor, err := h.vmdbLayer.FindVMByUserId(userId)
	if err != nil {
		log.Printf("Error fetching VMs from database: %v", err)
		return
	}
	defer cursor.Close(ctx)

	existingVMs := make(map[string]string)
	for cursor.Next(ctx) {
		var vm models.VM
		if err := cursor.Decode(&vm); err != nil {
			log.Printf("Error decoding VM from database: %v", err)
			continue
		}
		existingVMs[vm.UniqueId] = vm.VMId
	}

	// Create a set of fetched unique IDs for fast lookup
	fetchedUniqueIdSet := make(map[string]bool)
	for _, id := range fetchedUniqueIds {
		fetchedUniqueIdSet[id] = true
	}

	// Delete VMs that are no longer present
	for uniqueId, vmId := range existingVMs {
		if !fetchedUniqueIdSet[uniqueId] {
			err := h.vmdbLayer.DeleteVM(ctx, bson.M{"uniqueId": uniqueId, "userId": userId})
			if err != nil {
				log.Printf("Error deleting absent VM from database: %v", err)
			} else {
				log.Printf("Deleted absent VM with ID: %s", vmId)
			}
		}
	}
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
		Timeout:   5 * time.Second,
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
