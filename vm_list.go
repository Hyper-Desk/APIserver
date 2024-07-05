package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// VMInfo represents information about a VM or CT
type VMInfo struct {
	ID     string `json:"id" bson:"id"`
	Name   string `json:"name" bson:"name"`
	Status string `json:"status" bson:"status"`
}

// TokenClaims represents JWT claims
type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}

var (
	client         *mongo.Client
	vmCollection   *mongo.Collection
	tokenSecretKey []byte
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

	// JWT secret key
	tokenSecretKey = []byte(os.Getenv("TOKEN_SECRET"))
}

func vmListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the access token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
		return
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	accessToken := authHeaderParts[1]

	// Validate the access token and extract user ID
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return tokenSecretKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	userId := claims.UserId

	// Decode the request body into a slice of VMInfo structs
	var vmList []VMInfo
	if err := json.NewDecoder(r.Body).Decode(&vmList); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	// Save VM list to MongoDB for the specific user
	err = saveVMList(userId, vmList)
	if err != nil {
		log.Printf("Failed to save VM list to MongoDB: %v", err)
		http.Error(w, "Failed to save VM list", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("VM list saved successfully"))
}

// saveVMList saves the VM list to MongoDB for the specified user
func saveVMList(userId string, vmList []VMInfo) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete existing VM documents for the user
	filter := bson.M{"userId": userId}
	_, err := vmCollection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete existing VM documents: %v", err)
	}

	// Insert new VM documents
	var documents []interface{}
	for _, vm := range vmList {
		vmDoc := bson.M{
			"userId": userId,
			"id":     vm.ID,
			"name":   vm.Name,
			"status": vm.Status,
		}
		documents = append(documents, vmDoc)
	}

	_, err = vmCollection.InsertMany(ctx, documents)
	if err != nil {
		return fmt.Errorf("failed to insert VM documents: %v", err)
	}

	return nil
}
