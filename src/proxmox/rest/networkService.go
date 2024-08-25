package rest

import (
	"fmt"
	"hyperdesk/proxmox/models"
)

func fetchNetworks(req models.ProxmoxRequestBody) ([]string, error) {
	var creds = req.Creds
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/network", creds.Address, creds.Port, req.Node)

	netData, err := fetchProxmoxDataForURL(req.Creds, url, "GET")
	if err != nil {
		return nil, err
	}
	var ifaceList []string
	for _, item := range netData {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if itemType, typeOk := itemMap["type"].(string); typeOk && itemType == "bridge" {
				iface, ifaceOk := itemMap["iface"].(string)
				if ifaceOk {
					ifaceList = append(ifaceList, iface)
				}
			}
		}
	}

	return ifaceList, nil
}
