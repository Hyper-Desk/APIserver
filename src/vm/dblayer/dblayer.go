package dblayer

import (
	"context"
	"hyperdesk/vm/models"

	"go.mongodb.org/mongo-driver/mongo"
)

// DBLayer 인터페이스는 데이터베이스 작업을 정의합니다.
type DBLayer interface {
	InsertVM(vm models.VM) (*mongo.InsertOneResult, error)
	FindVMById(vmId string) (*models.VM, error)
	FindVMByUniqueId(uniqueId string) (*models.VM, error)
	FindVMByUserId(userId string) (*mongo.Cursor, error)
	UpdateVMStatus(vmId string, status string, userId string) (*mongo.UpdateResult, error)
	FindAvailableVMs() ([]models.VM, error)
	DeleteVM(ctx context.Context, filter interface{}) error
}
