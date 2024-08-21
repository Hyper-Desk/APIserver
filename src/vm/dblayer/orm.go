package dblayer

import (
	"context"
	"time"

	"hyperdesk/database"
	"hyperdesk/vm/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ORM struct {
	vmCollection *mongo.Collection
}

// NewORM은 새로운 ORM 인스턴스를 생성합니다.
func NewORM() (*ORM, error) {
	clientOptions := options.Client().ApplyURI(database.DataSource())
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, err
	}

	// Check the connection
	if err := client.Ping(context.Background(), nil); err != nil {
		return nil, err
	}

	return &ORM{
		vmCollection: client.Database(database.DbName()).Collection("vms"),
	}, nil
}

// InsertVM은 새로운 VM을 데이터베이스에 삽입합니다.
func (orm *ORM) InsertVM(vm models.VM) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return orm.vmCollection.InsertOne(ctx, vm)
}

// FindVMById는 주어진 vmId로 VM을 조회합니다.
func (orm *ORM) FindVMById(vmId string) (*models.VM, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var vm models.VM
	err := orm.vmCollection.FindOne(ctx, bson.M{"vmId": vmId}).Decode(&vm)
	return &vm, err
}

// FindVMByUniqueId는 주어진 uniqueId로 VM을 조회합니다.
func (orm *ORM) FindVMByUniqueId(uniqueId string) (*models.VM, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var vm models.VM
	err := orm.vmCollection.FindOne(ctx, bson.M{"uniqueId": uniqueId}).Decode(&vm)
	return &vm, err
}

// FindVMByUserId는 주어진 userId로 VM을 조회합니다.
func (orm *ORM) FindVMByUserId(userId string) (*mongo.Cursor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"userId": userId}
	cursor, err := orm.vmCollection.Find(ctx, filter)
	return cursor, err
}

// UpdateVMStatus는 VM의 상태와 사용자 ID를 업데이트합니다.
func (orm *ORM) UpdateVMStatus(vmId string, status string, userId string) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"status": status,
			"userId": userId,
		},
	}
	return orm.vmCollection.UpdateOne(ctx, bson.M{"vmId": vmId}, update, options.Update().SetUpsert(true))
}

// FindAvailableVMs는 상태가 "available"인 모든 VM을 조회합니다.
func (orm *ORM) FindAvailableVMs() ([]models.VM, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := orm.vmCollection.Find(ctx, bson.M{"status": "available"})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var vms []models.VM
	if err := cursor.All(ctx, &vms); err != nil {
		return nil, err
	}
	return vms, nil
}

// DeleteVM은 filter 조건에 해당하는 VM을 삭제합니다.
func (orm *ORM) DeleteVM(ctx context.Context, filter interface{}) error {
	_, err := orm.vmCollection.DeleteOne(ctx, filter)
	return err
}
