package rest

import (
	"context"
	"hyperdesk/proxmox/models"
	"time"

	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/mongo"
)

// getProxy는 주어진 사용자 ID에 해당하는 Proxy를 반환합니다.
func (h *Handler) getProxy(userId string) (*models.Proxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var proxy models.Proxy
	err := h.proxmoxdbLayer.FindProxyByUserId(ctx, userId, &proxy)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("프록시 정보를 찾을 수 없습니다.")
		}
		return nil, errors.WrapPrefix(err, "서버 오류입니다.", 1)
	}
	return &proxy, nil
}
