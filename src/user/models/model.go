package models

import (
    "github.com/dgrijalva/jwt-go"
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

type TokenClaims struct {
	UserId string `json:"userId"`
	jwt.StandardClaims
}