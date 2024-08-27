package dblayer

import (
	"context"
	"time"

	"hyperdesk/database"
	"hyperdesk/proxmox/models"

	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ORM struct {
	proxyCollection *mongo.Collection
}

func NewORM() (*ORM, error) {
	clientOptions := options.Client().ApplyURI(database.DataSource())
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to Connect to MongoDB with URI "+database.DataSource(), 1)
	}

	// Check the connection
	if err = client.Ping(context.Background(), nil); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to Ping to MongoDB", 1)
	}

	return &ORM{
		proxyCollection: client.Database(database.DbName()).Collection("proxies"),
	}, nil
}

func (orm *ORM) InsertProxy(proxy models.Proxy) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"userId": proxy.UserId}
	update := bson.M{
		"$set": bson.M{
			"address":   proxy.Address,
			"port":      proxy.Port,
			"proxmoxId": proxy.ProxmoxId,
		},
	}

	return orm.proxyCollection.UpdateOne(ctx, filter, update, opts)
}

func (orm *ORM) FindProxyByUserId(ctx context.Context, userId string, proxy *models.Proxy) error {
	err := orm.proxyCollection.FindOne(ctx, bson.M{"userId": userId}).Decode(proxy)
	return err
}
