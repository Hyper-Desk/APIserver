package rest

import (
	"context"
	"fmt"
	"hyperdesk/proxmox/models"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func fetchVMs(creds models.ProxmoxCredentials, userId string, h *Handler) ([]map[string]interface{}, error) {
	nodes, err := fetchProxmoxNodes(creds)
	if err != nil {
		return nil, err
	}

	var allData []map[string]interface{}
	for _, node := range nodes {
		nodeData, err := fetchNodeVMsAndCTs(creds, node, userId, h)
		if err != nil {
			log.Printf("Failed to fetch data for node %s: %v", node, err)
			continue
		}
		allData = append(allData, map[string]interface{}{
			node: nodeData,
		})
	}

	return allData, nil
}

func fetchNodeVMsAndCTs(creds models.ProxmoxCredentials, node string, userId string, h *Handler) (map[string]interface{}, error) {
	vmURL := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/qemu", creds.Address, creds.Port, node)
	ctURL := fmt.Sprintf("https://%s:%s/api2/json/nodes/%s/lxc", creds.Address, creds.Port, node)

	vmData, err := fetchProxmoxDataForURL(creds, vmURL, "GET")
	if err != nil {
		return nil, err
	}

	ctData, err := fetchProxmoxDataForURL(creds, ctURL, "GET")
	if err != nil {
		return nil, err
	}

	processedVMs, vmUniqueIds := processVMData(vmData, userId, h)
	processedCTs, ctUniqueIds := processVMData(ctData, userId, h)

	allUniqueIds := append(vmUniqueIds, ctUniqueIds...)
	deleteAbsentsVMs(allUniqueIds, userId, h)

	allData := map[string]interface{}{
		"vms": processedVMs,
		"cts": processedCTs,
	}

	return allData, nil
}

// processVMData processes the VM/CT data and checks if it's already registered.
func processVMData(data interface{}, userId string, h *Handler) ([]interface{}, []string) {
	processed := []interface{}{}
	uniqueIds := []string{}

	// Assuming `data` is an array of VMs/CTs
	vms := data.([]interface{})

	for _, vm := range vms {
		vmMap := vm.(map[string]interface{})

		vmid := fmt.Sprintf("%v", vmMap["vmid"]) // Convert vmid to string if it's not
		name := vmMap["name"].(string)

		// 소수점 둘째 자리까지 표시
		diskread := fmt.Sprintf("%.2f", vmMap["diskread"].(float64)/(1024*1024*1024)) // GB
		vmMap["diskread"] = diskread

		diskwrite := fmt.Sprintf("%.2f", vmMap["diskwrite"].(float64)/(1024*1024*1024)) // GB
		vmMap["diskwrite"] = diskwrite

		disk := fmt.Sprintf("%.2f", vmMap["disk"].(float64)/(1024*1024*1024)) // GB
		vmMap["disk"] = disk

		maxdisk := fmt.Sprintf("%.2f", vmMap["maxdisk"].(float64)/(1024*1024*1024)) // GB
		vmMap["maxdisk"] = maxdisk

		maxmem := fmt.Sprintf("%.2f", vmMap["maxmem"].(float64)/(1024*1024*1024)) // GB
		vmMap["maxmem"] = maxmem

		mem := fmt.Sprintf("%.2f", vmMap["mem"].(float64)/(1024*1024*1024)) // GB
		vmMap["mem"] = mem

		cpu := int(vmMap["cpus"].(float64))
		vmMap["cpus"] = cpu

		uniqueId := GenerateUniqueId(vmid, name, userId, maxdisk, maxmem, cpu)
		vmMap["uniqueId"] = uniqueId

		// Add the uniqueId to the list
		uniqueIds = append(uniqueIds, uniqueId)

		// Check if this VM/CT is already registered
		_, err := h.vmdbLayer.FindVMByUniqueId(uniqueId)

		if err == mongo.ErrNoDocuments {
			// VM is not yet registered
			vmMap["registered"] = false
		} else if err == nil {
			// VM is already registered
			vmMap["registered"] = true
		} else {
			// Handle potential errors
			log.Printf("Error checking if VM is registered: %v", err)
		}

		processed = append(processed, vmMap)
	}

	return processed, uniqueIds
}

// deleteAbsentsVMs deletes VMs from the collection that are no longer present in the Proxmox API response.
func deleteAbsentsVMs(fetchedUniqueIds []string, userId string, h *Handler) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fetch all VMs for the userId
	cursor, err := h.vmdbLayer.FindVMByUserId(userId)
	if err != nil {
		log.Printf("Error fetching VMs from database: %v", err)
		return
	}
	defer cursor.Close(ctx)

	existingVMs := make(map[string]string)
	for cursor.Next(ctx) {
		var vm models.VM
		if err := cursor.Decode(&vm); err != nil {
			log.Printf("Error decoding VM from database: %v", err)
			continue
		}
		existingVMs[vm.UniqueId] = vm.VMId
	}

	// Create a set of fetched unique IDs for fast lookup
	fetchedUniqueIdSet := make(map[string]bool)
	for _, id := range fetchedUniqueIds {
		fetchedUniqueIdSet[id] = true
	}

	// Delete VMs that are no longer present
	for uniqueId, vmId := range existingVMs {
		if !fetchedUniqueIdSet[uniqueId] {
			err := h.vmdbLayer.DeleteVM(ctx, bson.M{"uniqueId": uniqueId, "userId": userId})
			if err != nil {
				log.Printf("Error deleting absent VM from database: %v", err)
			} else {
				log.Printf("Deleted absent VM with ID: %s", vmId)
			}
		}
	}
}
