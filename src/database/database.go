package database

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type dbInfo struct {
	user     string
	pwd      string
	url      string
	database string
	port     string
}

// MongoDB는 연결 문자열에 이 정보를 사용합니다.

func DbName() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("!!Error loading .env file!!")
	}

	return os.Getenv("DBNAME")
}

func DataSource() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("!!Error loading .env file!!")
	}

	var db = dbInfo{
		os.Getenv("DBUSER"),
		os.Getenv("DBPWD"),
		os.Getenv("DBURL"),
		os.Getenv("DBNAME"),
		os.Getenv("PORT"),
	}

	var DataSource = "mongodb://" + db.user + ":" + db.pwd +
		"@" + db.url + ":" + db.port + "/" + db.database

	return DataSource
}
