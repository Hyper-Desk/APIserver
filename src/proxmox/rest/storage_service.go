package rest

import (
	"fmt"
	"hyperdesk/proxmox/models"
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
