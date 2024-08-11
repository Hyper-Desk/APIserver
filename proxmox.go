package main

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
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ProxmoxCredentials struct {
	Address  string `json:"address" bson:"address"`
	Port     string `json:"port" bson:"port"`
	UserId   string `json:"userId" bson:"userId"`
	Password string `json:"password" bson:"password"`
}

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}

func proxmoxVMListHandler(c *gin.Context) {
	// JWT 토큰에서 userId 추출
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

	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 토큰입니다."})
		return
	}

	userId := claims.UserId

	// 요청에서 Proxmox 자격 증명 받기
	var creds ProxmoxCredentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	// Proxy 정보 저장
	proxy := Proxy{
		UserId:  userId,
		Address: creds.Address,
		Port:    creds.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"userId": proxy.UserId}
	update := bson.M{
		"$set": bson.M{
			"address": proxy.Address,
			"port":    proxy.Port,
		},
	}

	_, err = proxyCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "프록시 정보 저장 실패"})
		return
	}

	// Proxmox API를 통해 VM/CT 정보 가져오기
	vmInfo, err := fetchProxmoxData(creds, userId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxmox VM 정보 가져오기 실패"})
		return
	}

	c.JSON(http.StatusOK, vmInfo)
}

// fetchProxmoxData fetches all VM and CT information from Proxmox.
func fetchProxmoxData(creds ProxmoxCredentials, userId string) (map[string]interface{}, error) {
	nodes, err := fetchProxmoxNodes(creds)
	if err != nil {
		return nil, err
	}

	allData := make(map[string]interface{})
	for _, node := range nodes {
		nodeData, err := fetchNodeVMsAndCTs(creds, node, userId)
		if err != nil {
			log.Printf("Failed to fetch data for node %s: %v", node, err)
			continue
		}
		allData[node] = nodeData
	}

	return allData, nil
}

// fetchProxmoxNodes fetches the list of nodes from Proxmox.
func fetchProxmoxNodes(creds ProxmoxCredentials) ([]string, error) {
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
func fetchNodeVMsAndCTs(creds ProxmoxCredentials, node string, userId string) (map[string]interface{}, error) {
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

	processedVMs, vmUniqueIds := processVMData(vmData, userId)
	processedCTs, ctUniqueIds := processVMData(ctData, userId)

	allUniqueIds := append(vmUniqueIds, ctUniqueIds...)
	deleteAbsentsVMs(allUniqueIds, userId)

	allData := map[string]interface{}{
		"vms": processedVMs,
		"cts": processedCTs,
	}

	return allData, nil
}

// generateUniqueId generates a unique ID based on VM/CT properties.
func generateUniqueId(vmid, name, userid string, maxdisk, maxmem, cpu int) string {
	data := fmt.Sprintf("%s:%s:%s:%d:%d:%d", vmid, name, userid, maxdisk, maxmem, cpu)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// processVMData processes the VM/CT data and checks if it's already registered.
func processVMData(data interface{}, userId string) ([]interface{}, []string) {
	processed := []interface{}{}
	uniqueIds := []string{}

	// Assuming `data` is an array of VMs/CTs
	vms := data.([]interface{})

	for _, vm := range vms {
		vmMap := vm.(map[string]interface{})

		vmid := fmt.Sprintf("%v", vmMap["vmid"]) // Convert vmid to string if it's not
		name := vmMap["name"].(string)
		maxdisk := int(vmMap["maxdisk"].(float64) / (1024 * 1024 * 1024)) // GB
		vmMap["maxdisk"] = maxdisk
		maxmem := int(vmMap["maxmem"].(float64) / (1024 * 1024)) // MB
		vmMap["maxmem"] = maxmem
		mem := int(vmMap["mem"].(float64) / (1024 * 1024)) // MB
		vmMap["mem"] = mem
		cpu := int(vmMap["cpus"].(float64))

		uniqueId := generateUniqueId(vmid, name, userId, maxdisk, maxmem, cpu)
		vmMap["uniqueId"] = uniqueId

		// Add the uniqueId to the list
		uniqueIds = append(uniqueIds, uniqueId)

		// Check if this VM/CT is already registered
		filter := bson.M{"uniqueId": uniqueId}
		var existingVM VM
		err := vmCollection.FindOne(context.Background(), filter).Decode(&existingVM)

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
func deleteAbsentsVMs(fetchedUniqueIds []string, userId string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fetch all VMs for the userId
	filter := bson.M{"userId": userId}
	cursor, err := vmCollection.Find(ctx, filter)
	if err != nil {
		log.Printf("Error fetching VMs from database: %v", err)
		return
	}
	defer cursor.Close(ctx)

	existingVMs := make(map[string]string)
	for cursor.Next(ctx) {
		var vm VM
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
			_, err := vmCollection.DeleteOne(ctx, bson.M{"uniqueId": uniqueId, "userId": userId})
			if err != nil {
				log.Printf("Error deleting absent VM from database: %v", err)
			} else {
				log.Printf("Deleted absent VM with ID: %s", vmId)
			}
		}
	}
}

// fetchProxmoxDataForURL fetches data from a specific URL on the Proxmox server.
func fetchProxmoxDataForURL(creds ProxmoxCredentials, url string) (interface{}, error) {
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

	return result["data"], nil
}

// getProxmoxToken gets an API token from the Proxmox server.
func getProxmoxToken(creds ProxmoxCredentials) (string, string, error) {
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
