package rest

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hyperdesk/proxmox/models"
	"io"
	"log"
	"net/http"
)

// fetchProxmoxDataForURL은 Proxmox API url을 통해 파라미터 method에 따른 요청을 보냅니다.
func fetchProxmoxDataForURL(creds models.ProxmoxCredentials, url string, method string, bodyData ...[]byte) ([]interface{}, error) {
	// GET 요청의 경우 body를 nil로 설정
	var bodyReader io.Reader
	if len(bodyData) > 0 && (method == "POST" || method == "PUT") {
		bodyReader = bytes.NewBuffer(bodyData[0])
	} else {
		bodyReader = nil
	}

	req, err := http.NewRequest(method, url, bodyReader)
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

	// POST/PUT 요청에 대해 Content-Type 설정
	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", "application/json")
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

	var data []interface{}
	var ok bool

	if data, ok = result["data"].([]interface{}); !ok {
		if mapData, ok := result["data"].(map[string]interface{}); ok {
			data = []interface{}{mapData}
		} else {
			return nil, fmt.Errorf("unexpected format for data")
		}
	}

	return data, nil
}

// GenerateUniqueId는 VM/CT 속성을 기반으로 고유 ID를 생성합니다.
func GenerateUniqueId(vmid, name, userid string, maxdisk string, maxmem string, cpu int) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%d", vmid, name, userid, maxdisk, maxmem, cpu)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
