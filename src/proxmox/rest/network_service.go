package rest

import (
	"fmt"
	"hyperdesk/proxmox/models"
)

func fetchNetworks(node string, token models.ProxmoxToken, proxy models.Proxy) ([]string, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/network", proxy.Address, proxy.Port, node)

	netData, err := fetchProxmoxDataForURL(token, url, "GET")
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
