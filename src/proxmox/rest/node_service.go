package rest

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hyperdesk/proxmox/models"
	"io"
	"net/http"
)

func fetchProxmoxNodes(token models.ProxmoxToken, proxy models.Proxy) ([]string, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/", proxy.Address, proxy.Port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "PVEAuthCookie="+token.Token)
	if token.CsrfToken != "" {
		req.Header.Set("CSRFPreventionToken", token.CsrfToken)
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
