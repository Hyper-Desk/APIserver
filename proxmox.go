package main

import (
	"context"
	"crypto/tls"
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
	vmInfo, err := fetchProxmoxData(creds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxmox VM 정보 가져오기 실패"})
		return
	}

	c.JSON(http.StatusOK, vmInfo)
}

// fetchProxmoxData fetches all VM and CT information from Proxmox.
func fetchProxmoxData(creds ProxmoxCredentials) (map[string]interface{}, error) {
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
func fetchNodeVMsAndCTs(creds ProxmoxCredentials, node string) (map[string]interface{}, error) {
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
