package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Van1sexboy/proj_avt/modules"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson" // сложных запросов
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

// Карта разрешений из ТЗ
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

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		fmt.Printf("Ошибка подключения к БД: %v\n", err)
		return
	}
	db = client.Database(dbName)
	fmt.Printf("Успех! Подключились к базе данных: %s\n", dbName)

	r := gin.Default()

	// 1. Начало входа (УЧИТЫВАЕМ ТИП: github/yandex)
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

		var redirectURL string
		if authType == "github" {
			clientID := os.Getenv("GITHUB_CLIENT_ID")
			redirectURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s&scope=user:email", clientID, tokenIn)
		} else if authType == "yandex" {
			clientID := os.Getenv("YANDEX_CLIENT_ID")
			redirectURL = fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=code&client_id=%s&state=%s", clientID, tokenIn)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "неизвестный тип авторизации"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"url": redirectURL})
	})

	// 2. ОБРАБОТКА CALLBACK (Логика обмена кода на email и JWT)
	r.GET("/auth/callback", func(c *gin.Context) {
		code := c.Query("code")
		tokenIn := c.Query("state")

		if code == "" || tokenIn == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "отсутствует код или state"})
			return
		}

		// Для простоты примера делаем логику GitHub (для Яндекса нужны свои URL)
		clientID := os.Getenv("GITHUB_CLIENT_ID")
		clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

		tokenURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)
		req, _ := http.NewRequest("POST", tokenURL, nil)
		req.Header.Set("Accept", "application/json")

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка запроса к GitHub"})
			return
		}
		defer resp.Body.Close()

		var tokenRes modules.GitHubTokenResponse
		json.NewDecoder(resp.Body).Decode(&tokenRes)

		req, _ = http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Authorization", "token "+tokenRes.AccessToken)
		resp, _ = httpClient.Do(req)
		defer resp.Body.Close()

		var userRes modules.GitHubUserResponse
		json.NewDecoder(resp.Body).Decode(&userRes)

		userEmail := userRes.Email
		if userEmail == "" {
			userEmail = userRes.Login + "@github.com"
		}

		// Поиск/Создание пользователя в Mongo
		var user modules.User
		err = db.Collection("users").FindOne(context.TODO(), bson.M{"email": userEmail}).Decode(&user)

		if err != nil {
			user = modules.User{
				Email:         userEmail,
				FullName:      "Аноним_" + tokenIn[:4],
				Roles:         []string{"Студент"},
				RefreshTokens: []string{},
			}
			res, _ := db.Collection("users").InsertOne(context.TODO(), user)
			user.ID = res.InsertedID.(primitive.ObjectID)
		}

		accessToken, refreshToken, _ := generateTokens(user.Email, user.Roles)

		// Сохраняем Refresh в БД пользователя
		db.Collection("users").UpdateOne(context.TODO(),
			bson.M{"email": user.Email},
			bson.M{"$push": bson.M{"refresh_tokens": refreshToken}},
		)

		// Обновляем статус временного входа
		db.Collection("states").UpdateOne(context.TODO(),
			bson.M{"token_in": tokenIn},
			bson.M{"$set": bson.M{
				"status":        "доступ предоставлен",
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			}},
		)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, "<h1>Успешно!</h1><p>Вернитесь в приложение.</p>")
	})

	// 3. Проверка статуса (для Web и Бота)
	r.GET("/auth/check", func(c *gin.Context) {
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

		c.JSON(http.StatusOK, gin.H{
			"status":        state.Status,
			"access_token":  state.AccessToken,
			"refresh_token": state.RefreshToken,
		})
	})

	// 4. Обновление токенов (Refresh Token Rotation)
	r.POST("/auth/refresh", func(c *gin.Context) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "нужен refresh_token"})
			return
		}

		token, err := jwt.Parse(body.RefreshToken, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "невалидный токен"})
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		email := claims["email"].(string)

		// Проверяем наличие токена у пользователя в массиве refresh_tokens
		var user modules.User
		err = db.Collection("users").FindOne(context.TODO(), bson.M{
			"email":          email,
			"refresh_tokens": body.RefreshToken,
		}).Decode(&user)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "токен отозван"})
			return
		}

		newA, newR, _ := generateTokens(user.Email, user.Roles)

		// Заменяем старый на новый (Rotation)
		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$pull": bson.M{"refresh_tokens": body.RefreshToken}})
		db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$push": bson.M{"refresh_tokens": newR}})

		c.JSON(http.StatusOK, gin.H{"access_token": newA, "refresh_token": newR})
	})

	// 5. Выход (Logout)
	r.POST("/auth/logout", func(c *gin.Context) {
		refresh := c.Query("refresh_token")
		all := c.Query("all") == "true"

		token, _ := jwt.Parse(refresh, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			email := claims["email"].(string)
			if all {
				db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": bson.M{"refresh_tokens": []string{}}})
			} else {
				db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$pull": bson.M{"refresh_tokens": refresh}})
			}
			c.JSON(http.StatusOK, gin.H{"status": "выход выполнен"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ошибка"})
	})

	r.Run(":" + os.Getenv("PORT"))
}

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
