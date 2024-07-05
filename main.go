package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

func main() {
	// .env 파일 로드
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// 핸들러 설정
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user/signup", registerHandler)
	mux.HandleFunc("/api/user/login", loginHandler)
	mux.HandleFunc("/api/user/refresh", refreshHandler)
	mux.HandleFunc("/api/user/vm_list", vmListHandler)
	mux.HandleFunc("/api/user/reserve", reserveHandler)

	// CORS 설정
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(mux)

	fmt.Println("서버가 포트 8080에서 실행 중입니다...")
	log.Fatal(http.ListenAndServe(":8080", corsHandler))
}
