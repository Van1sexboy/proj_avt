package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
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

// Карта разрешений
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

	// Авторизация  через GitHub/Yandex
	r.GET("/auth/login", func(c *gin.Context) {
		authType := c.Query("type")
		tokenIn := c.Query("token_in")

		if tokenIn == "" || authType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "нужны type и token_in"})
			return
		}

		// Состояние "не получен"
		saveLoginState(tokenIn)

		if authType == "github" {
			url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s&scope=user:email", os.Getenv("GITHUB_CLIENT_ID"), tokenIn)
			c.JSON(http.StatusOK, gin.H{"url": url})
		} else if authType == "yandex" {
			url := fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=code&client_id=%s&state=%s", os.Getenv("YANDEX_CLIENT_ID"), tokenIn)
			c.JSON(http.StatusOK, gin.H{"url": url})
		} else if authType == "code" {
			// Авторизация по коду
			code := generateRandomCode(6)
			db.Collection("auth_codes").InsertOne(context.TODO(), modules.AuthCodeEntry{
				Code:      code,
				TokenIn:   tokenIn,
				ExpiresAt: time.Now().Add(time.Minute),
			})
			c.JSON(http.StatusOK, gin.H{"code": code})
		}
	})

	// CALLBACKS
	r.GET("/auth/callback/github", handleGitHubCallback)
	r.GET("/auth/callback/yandex", handleYandexCallback)

	// Подтверждение кода для устройства, которое уже вошло
	r.POST("/auth/code/confirm", func(c *gin.Context) {
		var req struct {
			Code         string `json:"code"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Проверка код
		var codeEntry modules.AuthCodeEntry
		err := db.Collection("auth_codes").FindOne(context.TODO(), bson.M{"code": req.Code}).Decode(&codeEntry)
		if err != nil || time.Now().After(codeEntry.ExpiresAt) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "код не найден или устарел"})
			return
		}

		email, err := validateRefreshToken(req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "ошибка подтверждающего токена"})
			return
		}

		finishLogin(codeEntry.TokenIn, email)
		c.JSON(http.StatusOK, gin.H{"status": "доступ предоставлен"})
	})

	// Refresh
	r.POST("/auth/refresh", func(c *gin.Context) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		c.ShouldBindJSON(&body)

		email, err := validateRefreshToken(body.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh"})
			return
		}

		var user modules.User
		db.Collection("users").FindOne(context.TODO(), bson.M{"email": email, "refresh_tokens": body.RefreshToken}).Decode(&user)

		if user.Email == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
			return
		}

		newA, newR, _ := generateTokens(user.Email, user.Roles)

		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$pull": bson.M{"refresh_tokens": body.RefreshToken}})
		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$push": bson.M{"refresh_tokens": newR}})

		c.JSON(http.StatusOK, gin.H{"access_token": newA, "refresh_token": newR})
	})

	r.GET("/auth/check", checkStatusHandler)

	r.Run(":" + os.Getenv("PORT"))
}

// Хендлеры

func handleYandexCallback(c *gin.Context) {
	code := c.Query("code")
	tokenIn := c.Query("state")

	userEmail := "user@yandex.ru"
	finishLogin(tokenIn, userEmail)

	c.String(http.StatusOK, "Авторизация Яндекс успешна. Вернитесь в приложение.")
}

func finishLogin(tokenIn string, email string) {
	var user modules.User
	err := db.Collection("users").FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)

	if err != nil {
		// Если нет в базе, то...
		user = modules.User{
			Email:    email,
			FullName: "Аноним_" + generateRandomCode(4),
			Roles:    []string{"Студент"},
		}
		res, _ := db.Collection("users").InsertOne(context.TODO(), user)
		user.ID = res.InsertedID.(primitive.ObjectID)
	}

	acc, ref, _ := generateTokens(user.Email, user.Roles)

	// Сохраняем refresh в базу даных
	db.Collection("users").UpdateOne(context.TODO(), bson.M{"_id": user.ID}, bson.M{"$push": bson.M{"refresh_tokens": ref}})

	// Обновление статуса входа
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

	// Access: Только права и 1 минута жизни
	accClaims := jwt.MapClaims{
		"permissions": getPermissions(roles),
		"exp":         time.Now().Add(time.Minute).Unix(),
	}
	acc, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, accClaims).SignedString(secret)

	// Refresh: Почта и 7 дней жизни
	refClaims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
	}
	ref, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, refClaims).SignedString(secret)

	return acc, ref, nil
}

func validateRefreshToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims := token.Claims.(jwt.MapClaims)
	return claims["email"].(string), nil
}

func generateRandomCode(n int) string {
	const letters = "0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func saveLoginState(tokenIn string) {
	db.Collection("states").InsertOne(context.TODO(), modules.LoginState{
		TokenIn:   tokenIn,
		Status:    "не получен",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
}
