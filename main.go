package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Van1sexboy/proj_avt/modules"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

// Карта разрешений (Шаг 9)
var rolePermissions = map[string][]string{
	"Студент": {
		"course:testList", "course:user:add", "quest:read",
		"test:answer:read", "answer:update", "answer:del",
	},
	"Преподаватель": {
		"user:fullName:write", "course:info:write", "course:test:read",
		"course:test:write", "course:test:add", "course:test:del",
		"course:userList", "course:user:del", "course:del",
		"quest:list:read", "quest:update", "quest:del",
		"test:quest:del", "test:quest:add", "test:quest:update",
	},
	"Админ": {
		"user:list:read", "user:roles:read", "user:roles:write",
		"user:block:read", "user:block:write", "course:add", "quest:create",
	},
}

func main() {
	godotenv.Load()
	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("DB_NAME")

	client, _ := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	db = client.Database(dbName)
	fmt.Printf("Успех! Подключились к базе данных: %s\n", dbName)

	r := gin.Default()

	// 1. Начало входа
	r.GET("/auth/login", func(c *gin.Context) {
		authType := c.Query("type")
		tokenIn := c.Query("token_in")

		if tokenIn == "" || authType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "нужны type и token_in"})
			return
		}

		stateEntry := modules.LoginState{
			TokenIn:   tokenIn,
			Status:    "не получен",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}

		db.Collection("states").InsertOne(context.TODO(), stateEntry)

		clientID := os.Getenv("GITHUB_CLIENT_ID")
		redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s", clientID, tokenIn)

		c.JSON(http.StatusOK, gin.H{"url": redirectURL})
	})

	// 2. ОБРАБОТКА CALLBACK
	r.GET("/auth/callback", func(c *gin.Context) {
		code := c.Query("code")
		tokenIn := c.Query("state")

		if code == "" || tokenIn == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "отсутствует код или state"})
			return
		}

		userEmail := "test-user@example.com" // Заглушка

		var user modules.User
		err := db.Collection("users").FindOne(context.TODO(), map[string]string{"email": userEmail}).Decode(&user)

		if err != nil {
			user = modules.User{
				Email:    userEmail,
				FullName: "Аноним_" + tokenIn[:4],
				Roles:    []string{"Студент"},
			}
			db.Collection("users").InsertOne(context.TODO(), user)
		}

		accessToken, refreshToken, err := generateTokens(user.Email, user.Roles)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка генерации токенов"})
			return
		}

		db.Collection("states").UpdateOne(context.TODO(),
			map[string]string{"token_in": tokenIn},
			map[string]interface{}{
				"$set": map[string]string{
					"status":        "доступ предоставлен",
					"access_token":  accessToken,
					"refresh_token": refreshToken,
				},
			},
		)

		c.Writer.Write([]byte("<h1>Авторизация успешна!</h1><p>Пользователь и токены в базе.</p>"))
	})

	// 3. Проверка статуса входа (ТЕПЕРЬ ВНУТРИ main)
	r.GET("/auth/check", func(c *gin.Context) {
		tokenIn := c.Query("token_in")

		if tokenIn == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "нужен token_in"})
			return
		}

		var state modules.LoginState
		err := db.Collection("states").FindOne(context.TODO(), map[string]string{"token_in": tokenIn}).Decode(&state)

		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "не опознанный токен"})
			return
		}

		if time.Now().After(state.ExpiresAt) {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "время действия токена закончилось"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":        state.Status,
			"access_token":  state.AccessToken,
			"refresh_token": state.RefreshToken,
		})
	})

	// Запуск сервера всегда должен быть ПОСЛЕДНИМ в main
	r.Run(":" + os.Getenv("PORT"))
}

// Вспомогательные функции ВСЕГДА ВНЕ main
func getPermissions(roles []string) []string {
	permissions := []string{}
	seen := make(map[string]bool)
	for _, role := range roles {
		if perms, ok := rolePermissions[role]; ok {
			for _, p := range perms {
				if !seen[p] {
					seen[p] = true
					permissions = append(permissions, p)
				}
			}
		}
	}
	return permissions
}

func generateTokens(email string, roles []string) (string, string, error) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	accessClaims := jwt.MapClaims{
		"permissions": getPermissions(roles),
		"exp":         time.Now().Add(time.Minute * 1).Unix(),
	}
	accessToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)

	refreshClaims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
	}
	refreshToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(jwtSecret)

	return accessToken, refreshToken, nil
}
