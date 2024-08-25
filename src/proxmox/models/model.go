package models

import "github.com/dgrijalva/jwt-go"

// ProxmoxCredentials는 Proxmox 서버의 자격 증명을 정의합니다.
type ProxmoxCredentials struct {
	Address  string `json:"address"`
	Port     string `json:"port"`
	UserId   string `json:"userId"`
	Password string `json:"password"`
}

type ProxmoxRequestBody struct {
	Node  string             `json:"node"`
	Creds ProxmoxCredentials `json:"creds"`
}

// Proxy는 사용자와 관련된 프록시 정보를 정의합니다.
type Proxy struct {
	UserId  string `json:"userId" bson:"userId"`
	Address string `json:"address" bson:"address"`
	Port    string `json:"port" bson:"port"`
}

// TokenClaims는 JWT 토큰의 클레임을 정의합니다.
type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}

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

type StorageList struct {
	DiskStorage []interface{} `json:"diskStorage"`
	IsoStorage  []interface{} `json:"isoStorage"`
}
