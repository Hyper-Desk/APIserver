package rest

import (
	"fmt"
	"hyperdesk/proxmox/models"
	"log"
	"strings"
)

func fetchStorage(req models.ProxmoxRequestBody) (*models.StorageList, error) {
	var creds = req.Creds
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/storage", creds.Address, creds.Port, req.Node)

	storageData, err := fetchProxmoxDataForURL(req.Creds, url, "GET")
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

func fetchIsos(req models.ProxmoxRequestBody) ([]map[string]interface{}, error) {
	storageData, _ := fetchStorage(req)

	var isoData []map[string]interface{}
	for _, storage := range storageData.IsoStorage {
		storageMap, ok := storage.(map[string]interface{})
		if !ok {
			continue
		}
		storageName := storageMap["storage"].(string)
		iso, err := fetchIso(req, storageName)
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

func fetchIso(req models.ProxmoxRequestBody, storage string) ([]interface{}, error) {
	var creds = req.Creds
	url := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/storage/%s/content", creds.Address, creds.Port, req.Node, storage)

	isoData, err := fetchProxmoxDataForURL(req.Creds, url, "GET")
	if err != nil {
		return nil, err
	}

	return isoData, nil
}
