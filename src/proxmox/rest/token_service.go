package rest

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hyperdesk/proxmox/models"
	"io"
	"net/http"
	"strings"
	"time"
)

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
