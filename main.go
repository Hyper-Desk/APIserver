package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// .env 파일 로드
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Gin 라우터 생성
	r := gin.Default()

	// CORS 설정
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		c.Next()
	})

	// 핸들러 정의
	r.POST("/api/user/signup", func(c *gin.Context) {
		registerHandler(c)
	})

	r.POST("/api/user/login", func(c *gin.Context) {
		loginHandler(c)
	})

	r.POST("/api/user/refresh", func(c *gin.Context) {
		refreshHandler(c)
	})

	r.GET("/api/user/proxy", func(c *gin.Context) {
		proxyHandler(c)
	})

	r.POST("/api/proxmox/vm/", func(c *gin.Context) {
		proxmoxVMListHandler(c)
	})

	r.GET("/api/vm", func(c *gin.Context) {
		getVMPoolHandler(c)
	})

	r.POST("/api/vm/rent", func(c *gin.Context) {
		rentVMHandler(c)
	})

	r.POST("/api/vm/register", func(c *gin.Context) {
		registerVMHandler(c)
	})

	// 서버 실행
	log.Println("서버가 포트 8080에서 실행 중입니다...")
	if err := r.Run(":8080"); err != nil {
		log.Fatal("서버 실행 실패:", err)
	}
}
