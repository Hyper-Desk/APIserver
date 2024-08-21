package models

import (
    "github.com/dgrijalva/jwt-go"
)

type VM struct {
	VMId   string `json:"vmId" bson:"vmId"`
	Status string `json:"status" bson:"status"`
	UserId string `json:"userId" bson:"userId"`
}

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}