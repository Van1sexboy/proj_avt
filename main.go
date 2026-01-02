package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Van1sexboy/proj_avt/modules" // Твои структуры

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

func main() {
	godotenv.Load()
	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("DB_NAME")

	client, _ := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	db = client.Database(dbName)
	fmt.Printf("Успех! Подключились к базе данных: %s\n", dbName)

	// Инициализируем веб-сервер Gin
	r := gin.Default()

	// Реализуем ПУНКТ 1 из сценария: Запрос авторизации
	r.GET("/auth/login", func(c *gin.Context) {
		authType := c.Query("type")    // github или yandex
		tokenIn := c.Query("token_in") // токен входа от веб-клиента или бота

		if tokenIn == "" || authType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "нужны type и token_in"})
			return
		}

		// 1. Формируем структуру для сохранения в базу ("словарь")
		stateEntry := modules.LoginState{
			TokenIn:   tokenIn,
			Status:    "не получен",
			ExpiresAt: time.Now().Add(5 * time.Minute), // Устареет через 5 минут
		}

		// 2. Сохраняем в коллекцию "states"
		_, err := db.Collection("states").InsertOne(context.TODO(), stateEntry)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка базы данных"})
			return
		}

		// 3. Формируем ссылку на GitHub/Yandex (согласно сценарию)
		clientID := os.Getenv("GITHUB_CLIENT_ID")
		// Параметр state в OAuth2 идеально подходит для передачи нашего token_in
		redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s", clientID, tokenIn)

		// 4. Отправляем ссылку в ответ
		c.JSON(http.StatusOK, gin.H{"url": redirectURL})
	})

	r.Run(":" + os.Getenv("PORT")) // Запускаем сервер (например, на 8080)
}
