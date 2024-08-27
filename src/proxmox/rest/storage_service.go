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

	contentType := "images"
	storage := fetchStorageByContent(storageData, contentType)

	return &models.StorageList{
		DiskStorage: storage,
	}, nil
}

func fetchIsos(node string, token models.ProxmoxToken, proxy models.Proxy) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/storage", proxy.Address, proxy.Port, node)

	storageData, err := fetchProxmoxDataForURL(token, url, "GET")
	if err != nil {
		return nil, err
	}

	contentType := "iso"
	isoStorage := fetchStorageByContent(storageData, contentType)

	var isoData []map[string]interface{}
	for _, storage := range isoStorage {
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

	isoStorageData, err := fetchProxmoxDataForURL(token, url, "GET")
	if err != nil {
		return nil, err
	}

	var filteredIsoData []interface{}
	for _, iso := range isoStorageData {
		isoMap, ok := iso.(map[string]interface{})
		if !ok {
			continue
		}
		if content, exists := isoMap["content"].(string); exists {
			if strings.Contains(content, "iso") {
				filteredIsoData = append(filteredIsoData, iso)
			}
		}
	}

	return filteredIsoData, nil
}

func fetchStorageByContent(storageData []interface{}, contentType string) []interface{} {
	var retStorage []interface{}

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
			if strings.Contains(content, contentType) {
				retStorage = append(retStorage, storageMap)
			}
		}
	}
	return retStorage
}
