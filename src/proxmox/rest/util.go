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
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
)

// fetchProxmoxDataForURL은 Proxmox API url을 통해 파라미터 method에 따른 요청을 보냅니다.
func fetchProxmoxDataForURL(proxmoxToken models.ProxmoxToken, url string, method string, bodyData ...[]byte) ([]interface{}, error) {
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

	req.Header.Set("Authorization", "PVEAuthCookie="+proxmoxToken.Token)
	if proxmoxToken.CsrfToken != "" {
		req.Header.Set("CSRFPreventionToken", proxmoxToken.CsrfToken)
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

// getProxmoxTokenFromCookies는 쿠키에서 Proxmox 토큰과 CSRF 토큰을 추출합니다.
func getProxmoxTokenFromCookies(c *gin.Context) (models.ProxmoxToken, error) {
	token, err := c.Cookie("token")
	if err != nil {
		return models.ProxmoxToken{}, err
	}

	csrfToken, err := c.Cookie("csrfToken")
	if err != nil {
		return models.ProxmoxToken{}, err
	}

	retToken := models.ProxmoxToken{
		Token:     token,
		CsrfToken: csrfToken,
	}

	return retToken, nil
}

func (h *Handler) validateToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("Token not provided")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		return "", errors.New("Invalid token format")
	}

	accessToken := authHeaderParts[1]
	claims := &models.TokenClaims{}
	jwtToken, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return h.jwtKey, nil
	})

	if err != nil || !jwtToken.Valid {
		return "", errors.New("Invalid token")
	}

	return claims.UserId, nil
}
