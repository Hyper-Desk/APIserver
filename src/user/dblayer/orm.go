package dblayer

import (
	"context"
	"time"

	"hyperdesk/database"
	"hyperdesk/user/models"

	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ORM struct {
	userCollection  *mongo.Collection
	tokenCollection *mongo.Collection
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
		userCollection:  client.Database(database.DbName()).Collection("users"),
		tokenCollection: client.Database(database.DbName()).Collection("tokens"),
		proxyCollection: client.Database(database.DbName()).Collection("proxies"),
	}, nil
}

func (orm *ORM) InsertUser(user models.User) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return orm.userCollection.InsertOne(ctx, user)
}

func (orm *ORM) FindUserById(userId string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := orm.userCollection.FindOne(ctx, bson.M{"userId": userId}).Decode(&user)
	return &user, err
}

func (orm *ORM) InsertToken(token models.Token) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return orm.tokenCollection.InsertOne(ctx, token)
}

func (orm *ORM) UpdateToken(userId string, update interface{}) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return orm.tokenCollection.UpdateOne(ctx, bson.M{"userId": userId}, update, options.Update().SetUpsert(true))
}

func (orm *ORM) FindTokenByUserId(userId string) (*models.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var token models.Token
	err := orm.tokenCollection.FindOne(ctx, bson.M{"userId": userId}).Decode(&token)
	return &token, err
}

func (orm *ORM) FindProxyByUserId(userId string) (*models.Proxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var proxy models.Proxy
	err := orm.proxyCollection.FindOne(ctx, bson.M{"userId": userId}).Decode(&proxy)
	return &proxy, err
}
