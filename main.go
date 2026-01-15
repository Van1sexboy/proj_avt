package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Van1sexboy/proj_avt/modules"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

// Карта разрешений из ТЗ
var rolePermissions = map[string][]string{
	"Студент":       {"course:testList", "course:user:add", "quest:read", "test:answer:read", "answer:update", "answer:del"},
	"Преподаватель": {"user:fullName:write", "course:info:write", "course:test:read", "course:test:write", "course:test:add", "course:test:del", "course:userList", "course:user:del", "course:del", "quest:list:read", "quest:update", "quest:del", "test:quest:del", "test:quest:add", "test:quest:update"},
	"Админ":         {"user:list:read", "user:roles:read", "user:roles:write", "user:block:read", "user:block:write", "course:add", "quest:create"},
}

func main() {
	godotenv.Load()
	client, _ := mongo.Connect(context.TODO(), options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	db = client.Database(os.Getenv("DB_NAME"))

	r := gin.Default()

	// Маршруты авторизации
	r.GET("/auth/login", loginHandler)
	r.GET("/auth/check", checkStatusHandler)
	r.POST("/auth/refresh", refreshHandler)
	r.POST("/auth/logout", logoutHandler)

	// Callbacks
	r.GET("/auth/callback/github", handleGitHubCallback)
	r.GET("/auth/callback/yandex", handleYandexCallback)

	// Маршруты для  авторизации по коду
	r.POST("/auth/code/confirm", confirmCodeHandler)

	r.Run(":" + os.Getenv("PORT"))
}

// ХЕНДЛЕРЫ

func loginHandler(c *gin.Context) {
	authType := c.Query("type")
	tokenIn := c.Query("token_in")

	if tokenIn == "" || authType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "нужны type и token_in"})
		return
	}

	// Создание начальное состояние
	db.Collection("states").InsertOne(context.TODO(), modules.LoginState{
		TokenIn:   tokenIn,
		Status:    "не получен",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	if authType == "github" {
		url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s&scope=user:email", os.Getenv("GITHUB_CLIENT_ID"), tokenIn)
		c.JSON(http.StatusOK, gin.H{"url": url})
	} else if authType == "yandex" {
		url := fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=code&client_id=%s&state=%s", os.Getenv("YANDEX_CLIENT_ID"), tokenIn)
		c.JSON(http.StatusOK, gin.H{"url": url})
	} else if authType == "code" {
		code := generateDigits(6)
		db.Collection("auth_codes").InsertOne(context.TODO(), modules.AuthCodeEntry{
			Code:      code,
			TokenIn:   tokenIn,
			ExpiresAt: time.Now().Add(time.Minute),
		})
		c.JSON(http.StatusOK, gin.H{"code": code})
	}
}

func handleGitHubCallback(c *gin.Context) {
	code := c.Query("code")
	tokenIn := c.Query("state")

	// Обмен кода на токен Гитхаба
	tokenURL := "https://github.com/login/oauth/access_token"
	params := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s", os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET"), code)

	req, _ := http.NewRequest("POST", tokenURL+"?"+params, nil)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	var tokenRes modules.GitHubTokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenRes)

	// Получение email
	req, _ = http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
	resp, _ = client.Do(req)
	defer resp.Body.Close()

	var userRes modules.GitHubUserResponse
	json.NewDecoder(resp.Body).Decode(&userRes)

	email := userRes.Email
	if email == "" {
		email = userRes.Login + "@github.com"
	}

	finishLogin(tokenIn, email)
	c.String(http.StatusOK, "Успешно! Вернитесь в приложение.")
}

func handleYandexCallback(c *gin.Context) {
	code := c.Query("code")
	tokenIn := c.Query("state")

	if code == "" || tokenIn == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "отсутствует код или state"})
		return
	}

	// Яндекс требует параметры в формате x-www-form-urlencoded
	tokenURL := "https://oauth.yandex.ru/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", os.Getenv("YANDEX_CLIENT_ID"))
	data.Set("client_secret", os.Getenv("YANDEX_CLIENT_SECRET"))

	client := &http.Client{}
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка запроса к Яндекс OAuth"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Яндекс отклонил код авторизации"})
		return
	}

	var tokenRes modules.YandexTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка декодирования токена Яндекса"})
		return
	}

	// Используем полученный токен для запроса в Яндекс ID
	req, _ := http.NewRequest("GET", "https://login.yandex.ru/info?format=json", nil)

	req.Header.Set("Authorization", "OAuth "+tokenRes.AccessToken)

	resp, err = client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка получения данных из Яндекс ID"})
		return
	}
	defer resp.Body.Close()

	var userRes modules.YandexUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userRes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка декодирования данных пользователя"})
		return
	}

	userEmail := userRes.DefaultEmail
	if userEmail == "" {
		// Если основной почты нет, используем ID как идентификатор
		userEmail = userRes.ID + "@yandex.ru"
	}

	finishLogin(tokenIn, userEmail)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, "<h1>Успешно!</h1><p>Авторизация через Яндекс прошла успешно. Теперь вы можете вернуться в приложение.</p>")
}

func checkStatusHandler(c *gin.Context) {
	tokenIn := c.Query("token_in")
	var state modules.LoginState
	err := db.Collection("states").FindOne(context.TODO(), bson.M{"token_in": tokenIn}).Decode(&state)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "не опознанный токен"})
		return
	}

	if time.Now().After(state.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "время действия токена закончилось"})
		return
	}

	res := gin.H{"status": state.Status}
	if state.Status == "доступ предоставлен" {
		res["access_token"] = state.AccessToken
		res["refresh_token"] = state.RefreshToken
	}
	c.JSON(http.StatusOK, res)
}

func confirmCodeHandler(c *gin.Context) {
	var req struct {
		Code         string `json:"code"`
		RefreshToken string `json:"refresh_token"`
	}
	c.ShouldBindJSON(&req)

	var codeEntry modules.AuthCodeEntry
	err := db.Collection("auth_codes").FindOne(context.TODO(), bson.M{"code": req.Code}).Decode(&codeEntry)
	if err != nil || time.Now().After(codeEntry.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "код недействителен"})
		return
	}

	email, err := validateRefresh(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ошибка токена"})
		return
	}

	finishLogin(codeEntry.TokenIn, email)
	c.JSON(http.StatusOK, gin.H{"status": "доступ предоставлен"})
}

func refreshHandler(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	c.ShouldBindJSON(&body)

	email, err := validateRefresh(body.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "невалидный токен"})
		return
	}

	var user modules.User
	err = db.Collection("users").FindOne(context.TODO(), bson.M{"email": email, "refresh_tokens": body.RefreshToken}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "токен отозван"})
		return
	}

	newA, newR, _ := generateTokens(user.Email, user.Roles)

	// Ротация
	db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$pull": bson.M{"refresh_tokens": body.RefreshToken}})
	db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$push": bson.M{"refresh_tokens": newR}})

	c.JSON(http.StatusOK, gin.H{"access_token": newA, "refresh_token": newR})
}

func logoutHandler(c *gin.Context) {
	refresh := c.Query("refresh_token")
	all := c.Query("all") == "true"

	email, err := validateRefresh(refresh)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ошибка"})
		return
	}

	if all {
		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": bson.M{"refresh_tokens": []string{}}})
	} else {
		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$pull": bson.M{"refresh_tokens": refresh}})
	}
	c.JSON(http.StatusOK, gin.H{"status": "выход выполнен"})
}

// Вспомогательные

func finishLogin(tokenIn, email string) {
	var user modules.User
	err := db.Collection("users").FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		user = modules.User{
			Email:         email,
			FullName:      "Аноним_" + generateDigits(4),
			Roles:         []string{"Студент"},
			RefreshTokens: []string{},
		}
		res, _ := db.Collection("users").InsertOne(context.TODO(), user)
		user.ID = res.InsertedID.(primitive.ObjectID)
	}

	acc, ref, _ := generateTokens(user.Email, user.Roles)

	db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$push": bson.M{"refresh_tokens": ref}})
	db.Collection("states").UpdateOne(context.TODO(), bson.M{"token_in": tokenIn}, bson.M{
		"$set": bson.M{
			"status":        "доступ предоставлен",
			"access_token":  acc,
			"refresh_token": ref,
		},
	})
}

func generateTokens(email string, roles []string) (string, string, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))

	acc, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"permissions": getPermissions(roles),
		"exp":         time.Now().Add(time.Minute).Unix(),
	}).SignedString(secret)

	ref, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
	}).SignedString(secret)

	return acc, ref, nil
}

func validateRefresh(str string) (string, error) {
	token, err := jwt.Parse(str, func(t *jwt.Token) (interface{}, error) { return []byte(os.Getenv("JWT_SECRET")), nil })
	if err != nil || !token.Valid {
		return "", err
	}
	return token.Claims.(jwt.MapClaims)["email"].(string), nil
}

func getPermissions(roles []string) []string {
	res := []string{}
	seen := make(map[string]bool)
	for _, r := range roles {
		for _, p := range rolePermissions[r] {
			if !seen[p] {
				seen[p] = true
				res = append(res, p)
			}
		}
	}
	return res
}

func generateDigits(n int) string {
	res := ""
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		res += num.String()
	}
	return res
}
