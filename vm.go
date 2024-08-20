package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// VM 구조체 정의
type VM struct {
	Status   string `json:"status" bson:"status"`
	UserId   string `json:"userId" bson:"userId"`
	CPU      int    `json:"cpu" bson:"cpu"`
	MaxDisk  string `json:"maxdisk" bson:"maxdisk"`
	MaxMem   string `json:"maxmem" bson:"maxmem"`
	Name     string `json:"name" bson:"name"`
	VMId     string `json:"vmid" bson:"vmid"`
	UniqueId string `json:"uniqueId" bson:"uniqueId"`
}

var (
	client       *mongo.Client
	vmCollection *mongo.Collection
)

func init() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize MongoDB client
	mongoURI := os.Getenv("MONGO_URI")

	// Set up client options
	clientOptions := options.Client().ApplyURI(mongoURI)

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Error connecting to MongoDB: %v", err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatalf("Error pinging MongoDB: %v", err)
	}

	// Set up MongoDB collections
	dbName := os.Getenv("MONGO_DBNAME")
	vmCollection = client.Database(dbName).Collection("vms")

}

// VM Pool을 가져오는 GET 요청 핸들러
func getVMPoolHandler(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := vmCollection.Find(ctx, bson.M{"status": "available"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}
	defer cursor.Close(ctx)

	var vms []VM
	if err = cursor.All(ctx, &vms); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	c.JSON(http.StatusOK, vms)
}

// VM Pool에서 빌리는 POST 요청 핸들러
func rentVMHandler(c *gin.Context) {
	var req struct {
		VMId   string `json:"vmId"`
		UserId string `json:"userId"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"vmid": req.VMId, "status": "available"}
	update := bson.M{"$set": bson.M{"status": "rented", "userId": req.UserId}}

	result, err := vmCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "사용 가능한 VM을 찾을 수 없습니다."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "VM rented successfully"})
}

// VM Pool에 빌려줄 VM을 등록하는 POST 요청 핸들러
func registerVMHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "토큰이 제공되지 않았습니다."})
		return
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 토큰 형식입니다."})
		return
	}

	accessToken := authHeaderParts[1]

	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 액세스 토큰입니다."})
		return
	}

	var vm VM
	if err := c.BindJSON(&vm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	// VM의 상태와 사용자 ID 설정
	vm.Status = "available"
	vm.UserId = claims.UserId

	// Unique ID 생성 및 할당
	vm.UniqueId = generateUniqueId(vm.VMId, vm.Name, vm.UserId, vm.MaxDisk, vm.MaxMem, vm.CPU)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = vmCollection.InsertOne(ctx, vm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "VM registered successfully", "uniqueId": vm.UniqueId})
}
