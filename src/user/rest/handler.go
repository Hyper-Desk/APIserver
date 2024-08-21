package rest

import (
	"hyperdesk/user/dblayer"
	"hyperdesk/user/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	dbLayer dblayer.DBLayer
	jwtKey  []byte
}

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}

func NewHandler() (*Handler, error) {
	dbLayer, err := dblayer.NewORM()

	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create a new ORM", 1)
	}

	jwtKey := []byte(os.Getenv("TOKEN_SECRET"))

	return &Handler{
		dbLayer: dbLayer,
		jwtKey:  jwtKey,
	}, nil
}

func (h *Handler) RegisterHandler(c *gin.Context) {
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	if h.dbLayer == nil {
		log.Printf("dbLayer is nil")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	_, err := h.dbLayer.FindUserById(user.UserId)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			log.Printf("Error checking for existing user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
			return
		}
	} else {
		c.JSON(http.StatusConflict, gin.H{"error": "이미 존재하는 아이디입니다."})
		return
	}

	_, err = h.dbLayer.InsertUser(user)
	if err != nil {
		log.Printf("Error inserting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류입니다."})
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*15, h.jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 생성 실패"})
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7, h.jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "리프레시 토큰 생성 실패"})
		return
	}

	_, err = h.dbLayer.InsertToken(models.Token{UserId: user.UserId, AccessToken: accessToken, RefreshToken: refreshToken})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 저장 실패"})
		return
	}

	// Refresh Token을 HttpOnly 쿠키로 설정
	c.SetCookie(
		"refresh_token",                 // 쿠키 이름
		refreshToken,                    // 쿠키 값
		int(time.Hour*24*7/time.Second), // 쿠키 만료 시간 (7일)
		"/",                             // 쿠키 유효 경로
		"",                              // 도메인 (기본적으로 현재 도메인)
		true,                            // HTTPS 사용 여부 (true로 설정하면 HTTPS에서만 전송)
		true,                            // HttpOnly 설정 (true로 설정하면 JavaScript에서 접근 불가)
	)

	// 액세스 토큰과 사용자 ID를 JSON 응답으로 반환
	c.JSON(http.StatusCreated, gin.H{
		"userId":      user.UserId,
		"accessToken": accessToken,
	})
}

func (h *Handler) LoginHandler(c *gin.Context) {
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	result, err := h.dbLayer.FindUserById(user.UserId)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "사용자 ID가 잘못되었습니다."})
		return
	}

	if result.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "사용자 비밀번호가 잘못되었습니다."})
		return
	}

	accessToken, err := generateJWT(user.UserId, time.Minute*15, h.jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 생성 실패"})
		return
	}

	refreshToken, err := generateJWT(user.UserId, time.Hour*24*7, h.jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "리프레시 토큰 생성 실패"})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	}
	_, err = h.dbLayer.UpdateToken(result.UserId, update)
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

func (h *Handler) RefreshHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 요청입니다."})
		return
	}

	claims := &models.TokenClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return h.jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "잘못된 리프레시 토큰입니다."})
		return
	}

	result, err := h.dbLayer.FindTokenByUserId(claims.UserId)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "리프레시 토큰을 찾을 수 없습니다."})
		return
	}

	if result.RefreshToken != req.RefreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "리프레시 토큰이 일치하지 않습니다."})
		return
	}

	accessToken, err := generateJWT(result.UserId, time.Minute*15, h.jwtKey)
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
	_, err = h.dbLayer.UpdateToken(result.UserId, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "액세스 토큰 업데이트 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"accessToken": accessToken})
}

func generateJWT(userId string, duration time.Duration, jwtKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": userId,
		"exp":    time.Now().Add(duration).Unix(),
	})
	return token.SignedString(jwtKey)
}
