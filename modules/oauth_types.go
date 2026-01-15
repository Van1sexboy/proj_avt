package modules

import "time"

// GitHub
type GitHubTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type GitHubUserResponse struct {
	Email string `json:"email"`
	Login string `json:"login"`
}

// Yandex
type YandexTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type YandexUserResponse struct {
	DefaultEmail string `json:"default_email"`
	ID           string `json:"id"`
	RealName     string `json:"real_name"`
}

// Code Authentication
type AuthCodeEntry struct {
	Code      string    `bson:"code"`
	TokenIn   string    `bson:"token_in"`
	ExpiresAt time.Time `bson:"expires_at"`
}
