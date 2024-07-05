package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var jwtKey = []byte("my_secret_key")

type User struct {
	UserId   string `json:"userId" bson:"userId"`
	Password string `json:"password" bson:"password"`
}

type Token struct {
	UserId       string `json:"userId" bson:"userId"`
	AccessToken  string `json:"accessToken" bson:"accessToken"`
	RefreshToken string `json:"refreshToken" bson:"refreshToken"`
}

var (
	userCollection  *mongo.Collection
	tokenCollection *mongo.Collection
)

func init() {
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

	client.Ping(ctx, readpref.Primary())

	// 데이터베이스와 컬렉션 설정
	userCollection = client.Database("testdb").Collection("users")
	tokenCollection = client.Database("testdb").Collection("tokens")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "허용되지 않는 메소드입니다.", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "잘못된 요청입니다.", http.StatusBadRequest)
		return
	}

	var user User
	user.UserId = r.FormValue("userId")
	user.Password = r.FormValue("password")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 사용자 ID 중복 확인
	count, err := userCollection.CountDocuments(ctx, bson.M{"userId": user.UserId})
	if err != nil {
		http.Error(w, "서버 오류입니다.", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "이미 존재하는 사용자입니다.", http.StatusConflict)
		return
	}

	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "서버 오류입니다.", http.StatusInternalServerError)
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*15)
	if err != nil {
		http.Error(w, "액세스 토큰 생성 실패", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7)
	if err != nil {
		http.Error(w, "리프레시 토큰 생성 실패", http.StatusInternalServerError)
		return
	}

	_, err = tokenCollection.InsertOne(ctx, Token{UserId: user.UserId, AccessToken: accessToken, RefreshToken: refreshToken})
	if err != nil {
		http.Error(w, "토큰 저장 실패", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"accessToken": accessToken, "refreshToken": refreshToken})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "허용되지 않는 메소드입니다.", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "잘못된 요청입니다.", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result User
	err := userCollection.FindOne(ctx, bson.M{"userId": user.UserId}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "사용자 ID 또는 비밀번호가 잘못되었습니다.", http.StatusUnauthorized)
		} else {
			http.Error(w, "서버 오류입니다.", http.StatusInternalServerError)
		}
		return
	}

	if result.Password != user.Password {
		http.Error(w, "사용자 ID 또는 비밀번호가 잘못되었습니다.", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*15)
	if err != nil {
		http.Error(w, "액세스 토큰 생성 실패", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7)
	if err != nil {
		http.Error(w, "리프레시 토큰 생성 실패", http.StatusInternalServerError)
		return
	}

	_, err = tokenCollection.InsertOne(ctx, Token{UserId: user.UserId, AccessToken: accessToken, RefreshToken: refreshToken})
	if err != nil {
		http.Error(w, "토큰 저장 실패", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"accessToken": accessToken, "refreshToken": refreshToken})
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "허용되지 않는 메소드입니다.", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "잘못된 요청입니다.", http.StatusBadRequest)
		return
	}

	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "잘못된 리프레시 토큰입니다.", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result Token
	err = tokenCollection.FindOne(ctx, bson.M{"refreshToken": req.RefreshToken}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "리프레시 토큰을 찾을 수 없습니다.", http.StatusUnauthorized)
		} else {
			http.Error(w, "서버 오류입니다.", http.StatusInternalServerError)
		}
		return
	}

	accessToken, err := generateJWT(result.UserId, time.Minute*15)
	if err != nil {
		http.Error(w, "액세스 토큰 생성 실패", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"accessToken": accessToken})
}

func generateJWT(userId string, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": userId,
		"exp":    time.Now().Add(duration).Unix(),
	})
	return token.SignedString(jwtKey)
}
