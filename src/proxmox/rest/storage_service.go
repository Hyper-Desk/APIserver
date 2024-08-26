package rest

import (
	"fmt"
	"hyperdesk/proxmox/models"
	"log"
	"strings"
)

func fetchStorage(node string, token models.ProxmoxToken, proxy models.Proxy) (*models.StorageList, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/storage", proxy.Address, proxy.Port, node)

	storageData, err := fetchProxmoxDataForURL(token, url, "GET")
	if err != nil {
		return nil, err
	}

	var diskStorage []interface{}
	var isoStorage []interface{}

	for _, storage := range storageData {
		storageMap, ok := storage.(map[string]interface{})
		if !ok {
			continue
		}

		if avail, exists := storageMap["avail"].(float64); exists {
			storageMap["avail"] = fmt.Sprintf("%.2f", avail/(1024*1024*1024))
		}
		if total, exists := storageMap["total"].(float64); exists {
			storageMap["total"] = fmt.Sprintf("%.2f", total/(1024*1024*1024))
		}
		if used, exists := storageMap["used"].(float64); exists {
			storageMap["used"] = fmt.Sprintf("%.2f", used/(1024*1024*1024))
		}

		if content, exists := storageMap["content"].(string); exists {
			if strings.Contains(content, "images") {
				diskStorage = append(diskStorage, storageMap)
			}
			if strings.Contains(content, "iso") {
				isoStorage = append(isoStorage, storageMap)
			}
		}
	}

	return &models.StorageList{
		DiskStorage: diskStorage,
		IsoStorage:  isoStorage,
	}, nil
}

func fetchIsos(node string, token models.ProxmoxToken, proxy models.Proxy) ([]map[string]interface{}, error) {
	storageData, _ := fetchStorage(node, token, proxy)

	var isoData []map[string]interface{}
	for _, storage := range storageData.IsoStorage {
		storageMap, ok := storage.(map[string]interface{})
		if !ok {
			continue
		}
		storageName := storageMap["storage"].(string)
		iso, err := fetchIso(node, storageName, token, proxy)
		if err != nil {
			log.Printf("Failed to fetch data for node %s: %v", storage, err)
			continue
		}
		isoData = append(isoData, map[string]interface{}{
			storageName: iso,
		})
	}

	return isoData, nil
}

func fetchIso(node string, storage string, token models.ProxmoxToken, proxy models.Proxy) ([]interface{}, error) {

	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/storage/%s/content", proxy.Address, proxy.Port, node, storage)

	isoData, err := fetchProxmoxDataForURL(token, url, "GET")
	if err != nil {
		return nil, err
	}

	return isoData, nil
}
