package models

import (
	"github.com/dgrijalva/jwt-go"
)

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

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}
