package dblayer

import (
	"hyperdesk/proxmox/models" // models 패키지를 임포트
    "context"
	"go.mongodb.org/mongo-driver/mongo"
)

// DBLayer 인터페이스는 데이터베이스와의 상호작용을 정의합니다.
type DBLayer interface {
	InsertProxy(proxy models.Proxy) (*mongo.UpdateResult, error)
	FindProxyByUserId(ctx context.Context, userId string, proxy *models.Proxy) error
}
