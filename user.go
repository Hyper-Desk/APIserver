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

type User struct {
	UserId   string `json:"userId" bson:"userId"`
	Password string `json:"password" bson:"password"`
}

type Token struct {
	UserId       string `json:"userId" bson:"userId"`
	AccessToken  string `json:"accessToken" bson:"accessToken"`
	RefreshToken string `json:"refreshToken" bson:"refreshToken"`
}

type Proxy struct {
	UserId  string `json:"userId" bson:"userId"`
	Address string `json:"address" bson:"address"`
	Port    string `json:"port" bson:"port"`
}

var (
	userCollection  *mongo.Collection
	tokenCollection *mongo.Collection
	proxyCollection *mongo.Collection
	jwtKey          []byte
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize MongoDB client
	mongoURI := os.Getenv("MONGO_URI")
	jwtKey = []byte(os.Getenv("TOKEN_SECRET"))

	// Set up client options
	clientOptions := options.Client().ApplyURI(mongoURI)

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Error connecting to MongoDB: %v", err)
	}

	client.Ping(ctx, readpref.Primary())

	// 데이터베이스와 컬렉션 설정
	userCollection = client.Database("testdb").Collection("users")
	tokenCollection = client.Database("testdb").Collection("tokens")
	proxyCollection = client.Database("testdb").Collection("proxies")
}

func registerHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 사용자 ID 중복 확인
	count, err := userCollection.CountDocuments(ctx, bson.M{"userId": user.UserId})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "이미 존재하는 사용자입니다."})
		return
	}

	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 생성 실패"})
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "리프레시 토큰 생성 실패"})
		return
	}

	_, err = tokenCollection.InsertOne(ctx, Token{UserId: user.UserId, AccessToken: accessToken, RefreshToken: refreshToken})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 저장 실패"})
		return
	}

	c.SetSameSite(http.SameSiteNoneMode)
	// Refresh Token을 HttpOnly 쿠키로 설정
	c.SetCookie(
		"refreshToken",
		refreshToken,
		int(time.Hour*24*7/time.Second), // 쿠키 만료 시간을 7일로 설정
		"/",
		"",   // 도메인 설정 (기본: 현재 도메인)
		true, // HTTPS 설정 여부 (true로 설정하면 HTTPS에서만 전송)
		true, // HttpOnly 설정 (JavaScript에서 접근 불가)
	)

	c.JSON(http.StatusCreated, gin.H{
		"userId":      user.UserId,
		"accessToken": accessToken,
	})
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result User
	err := userCollection.FindOne(ctx, bson.M{"userId": user.UserId}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "사용자 ID 또는 비밀번호가 잘못되었습니다."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		}
		return
	}

	if result.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "사용자 ID 또는 비밀번호가 잘못되었습니다."})
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 생성 실패"})
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "리프레시 토큰 생성 실패"})
		return
	}

	// userId로 필터링하여 토큰 업데이트 또는 새로 삽입
	update := bson.M{
		"$set": bson.M{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	}
	_, err = tokenCollection.UpdateOne(ctx, bson.M{"userId": user.UserId}, update, options.Update().SetUpsert(true))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 저장 실패"})
		return
	}

	c.SetSameSite(http.SameSiteNoneMode)
	// Refresh Token을 HttpOnly 쿠키로 설정
	c.SetCookie(
		"refreshToken",
		refreshToken,
		int(time.Hour*24*7/time.Second), // 쿠키 만료 시간을 7일로 설정
		"/",
		"",   // 도메인 설정 (기본: 현재 도메인)
		true, // HTTPS 설정 여부 (true로 설정하면 HTTPS에서만 전송)
		true, // HttpOnly 설정 (JavaScript에서 접근 불가)
	)

	c.JSON(http.StatusCreated, gin.H{
		"userId":      user.UserId,
		"accessToken": accessToken,
	})
}

func refreshHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 리프레시 토큰입니다."})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// userId를 이용해 tokens 컬렉션에서 검색
	var result Token
	err = tokenCollection.FindOne(ctx, bson.M{"userId": claims.UserId}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "리프레시 토큰을 찾을 수 없습니다."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		}
		return
	}

	// Refresh token이 일치하는지 확인
	if result.RefreshToken != req.RefreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "리프레시 토큰이 일치하지 않습니다."})
		return
	}

	accessToken, err := generateJWT(result.UserId, time.Minute*15)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 생성 실패"})
		return
	}

	// 새로운 액세스 토큰으로 업데이트
	update := bson.M{
		"$set": bson.M{
			"accessToken": accessToken,
		},
	}
	_, err = tokenCollection.UpdateOne(ctx, bson.M{"userId": claims.UserId}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 업데이트 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"accessToken": accessToken})
}

func proxyHandler(c *gin.Context) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result Proxy
	err = proxyCollection.FindOne(ctx, bson.M{"userId": claims.UserId}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "프록시 정보를 찾을 수 없습니다."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

func generateJWT(userId string, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": userId,
		"exp":    time.Now().Add(duration).Unix(),
	})
	return token.SignedString(jwtKey)
}
