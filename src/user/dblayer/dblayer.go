package dblayer

import (
	"hyperdesk/user/models" // models 패키지를 임포트

	"go.mongodb.org/mongo-driver/mongo"
)

type DBLayer interface {
	InsertUser(user models.User) (*mongo.InsertOneResult, error)
	FindUserById(userId string) (*models.User, error)
	InsertToken(token models.Token) (*mongo.InsertOneResult, error)
	UpdateToken(userId string, update interface{}) (*mongo.UpdateResult, error)
	FindTokenByUserId(userId string) (*models.Token, error)
	FindProxyByUserId(userId string) (*models.Proxy, error)
}
