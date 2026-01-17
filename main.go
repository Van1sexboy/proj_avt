package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func main() {
	godotenv.Load()

	client, _ := mongo.Connect(context.TODO(), options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	db = client.Database(os.Getenv("DB_NAME"))

	r := gin.Default()

	// CORS для локального фронта (Vite:5173)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Маршруты авторизации
	r.GET("/auth/login", loginHandler)
	r.GET("/auth/check", checkStatusHandler)
	r.POST("/auth/refresh", refreshHandler)
	r.POST("/auth/logout", logoutHandler)

	// Callbacks
	r.GET("/auth/callback/github", handleGitHubCallback)
	r.GET("/auth/callback/yandex", handleYandexCallback)

	// Авторизация по коду
	r.POST("/auth/code/confirm", confirmCodeHandler)

	r.Run(":" + os.Getenv("PORT"))
}

// -------------------- ХЕНДЛЕРЫ --------------------

func loginHandler(c *gin.Context) {
	authType := c.Query("type")
	tokenIn := c.Query("token_in")

	if tokenIn == "" || authType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "нужны type и token_in"})
		return
	}

	// Создаём/обновляем state
	db.Collection("states").InsertOne(context.TODO(), modules.LoginState{
		TokenIn:   tokenIn,
		Status:    "не получен",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	if authType == "github" {
		u := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&state=%s&scope=user:email",
			os.Getenv("GITHUB_CLIENT_ID"),
			url.QueryEscape(tokenIn),
		)
		c.JSON(http.StatusOK, gin.H{"url": u})
		return
	}

	if authType == "yandex" {
		u := fmt.Sprintf(
			"https://oauth.yandex.ru/authorize?response_type=code&client_id=%s&state=%s",
			os.Getenv("YANDEX_CLIENT_ID"),
			url.QueryEscape(tokenIn),
		)
		c.JSON(http.StatusOK, gin.H{"url": u})
		return
	}

	if authType == "code" {
		code := generateDigits(6)
		db.Collection("auth_codes").InsertOne(context.TODO(), modules.AuthCodeEntry{
			Code:      code,
			TokenIn:   tokenIn,
			ExpiresAt: time.Now().Add(time.Minute),
		})
		c.JSON(http.StatusOK, gin.H{"code": code})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "неизвестный type"})
}

func handleGitHubCallback(c *gin.Context) {
	code := c.Query("code")
	tokenIn := c.Query("state")
	authErr := c.Query("error")

	if authErr != "" {
		updateLoginState(tokenIn, "в доступе отказано", "", "")
		c.String(http.StatusUnauthorized, "Авторизация отклонена.")
		return
	}

	if code == "" || tokenIn == "" {
		updateLoginState(tokenIn, "в доступе отказано", "", "")
		c.JSON(http.StatusBadRequest, gin.H{"error": "отсутствует code или state"})
		return
	}

	// Обмен кода на токен GitHub
	tokenURL := "https://github.com/login/oauth/access_token"
	params := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s",
		os.Getenv("GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
		code,
	)

	req, _ := http.NewRequest("POST", tokenURL+"?"+params, nil)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка запроса к GitHub OAuth"})
		return
	}
	defer resp.Body.Close()

	var tokenRes modules.GitHubTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка декодирования токена GitHub"})
		return
	}

	// Получение email
	req, _ = http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)

	resp, err = client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка получения данных из GitHub"})
		return
	}
	defer resp.Body.Close()

	var userRes modules.GitHubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userRes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка декодирования данных пользователя"})
		return
	}

	email := userRes.Email
	if email == "" {
		email = userRes.Login + "@github.com"
	}

	finishLogin(tokenIn, email)

	// ВАЖНО: возвращаем на /login и пробрасываем token_in,
	// чтобы фронт не создавал новый token_in и не ломал polling.
	c.Redirect(http.StatusFound, getFrontendRedirectURLWithTypeAndToken("github", tokenIn))
}

func handleYandexCallback(c *gin.Context) {
	code := c.Query("code")
	tokenIn := c.Query("state")
	authErr := c.Query("error")

	if authErr != "" {
		updateLoginState(tokenIn, "в доступе отказано", "", "")
		c.String(http.StatusUnauthorized, "Авторизация отклонена.")
		return
	}

	if code == "" || tokenIn == "" {
		updateLoginState(tokenIn, "в доступе отказано", "", "")
		c.JSON(http.StatusBadRequest, gin.H{"error": "отсутствует code или state"})
		return
	}

	// Яндекс: code -> access_token
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
		updateLoginState(tokenIn, "в доступе отказано", "", "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Яндекс отклонил код авторизации"})
		return
	}

	var tokenRes modules.YandexTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка декодирования токена Яндекса"})
		return
	}

	// Получаем профиль
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
		userEmail = userRes.ID + "@yandex.ru"
	}

	finishLogin(tokenIn, userEmail)

	// ВАЖНО: возвращаем на /login и пробрасываем token_in
	c.Redirect(http.StatusFound, getFrontendRedirectURLWithTypeAndToken("yandex", tokenIn))
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
		db.Collection("states").DeleteOne(context.TODO(), bson.M{"token_in": tokenIn})
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
	_ = c.ShouldBindJSON(&req)

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

	var user modules.User
	err = db.Collection("users").FindOne(context.TODO(), bson.M{"email": email, "refresh_tokens": req.RefreshToken}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "токен отозван"})
		return
	}

	finishLogin(codeEntry.TokenIn, email)
	c.JSON(http.StatusOK, gin.H{"status": "доступ предоставлен"})
}

func refreshHandler(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.ShouldBindJSON(&body)

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

	newA, newR, _ := generateTokens(user)

	// Ротация refresh
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

// -------------------- ВСПОМОГАТЕЛЬНЫЕ --------------------

// Atomic auto-increment для user_id через MongoDB (counters collection)
func nextUserID() (int, error) {
	type counterDoc struct {
		ID  string `bson:"_id"`
		Seq int    `bson:"seq"`
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	res := db.Collection("counters").FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "user_id"},
		bson.M{"$inc": bson.M{"seq": 1}},
		opts,
	)

	var doc counterDoc
	if err := res.Decode(&doc); err != nil {
		return 0, err
	}
	return doc.Seq, nil
}

func finishLogin(tokenIn, email string) {
	var user modules.User

	err := db.Collection("users").FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err != nil {

		username := "user_" + generateDigits(6)
		if email != "" {
			if parts := strings.SplitN(email, "@", 2); len(parts) > 0 && parts[0] != "" {
				username = parts[0]
			}
		}

		uid, uidErr := nextUserID()
		if uidErr != nil {
			uid = int(time.Now().Unix() % 1000000) // fallback (на всякий)
		}

		user = modules.User{
			UserID:        uid,
			Username:      username,
			Email:         email,
			FullName:      "Аноним_" + generateDigits(4),
			Roles:         []string{"student"},
			Permissions:   []string{},
			RefreshTokens: []string{},
		}

		res, _ := db.Collection("users").InsertOne(context.TODO(), user)
		user.ID = res.InsertedID.(primitive.ObjectID)
	} else {
		// Если пользователь был создан раньше без user_id — проставим ему user_id
		if user.UserID == 0 {
			uid, uidErr := nextUserID()
			if uidErr != nil {
				uid = int(time.Now().Unix() % 1000000)
			}
			user.UserID = uid
			db.Collection("users").UpdateOne(context.TODO(), bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"user_id": uid}})
		}
	}

	acc, ref, _ := generateTokens(user)

	db.Collection("users").UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$push": bson.M{"refresh_tokens": ref}})
	updateLoginState(tokenIn, "доступ предоставлен", acc, ref)

	if acc != "" {
		notifyMainBackend(acc)
	}
}

func generateTokens(user modules.User) (string, string, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))

	// ✅ sub = ЧИСЛО (строкой), чтобы FastAPI мог сделать int(payload["sub"])
	acc, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":         fmt.Sprintf("%d", user.UserID),
		"fullName":    user.FullName,
		"username":    user.Username,
		"email":       user.Email,
		"roles":       user.Roles,
		"permissions": user.Permissions,
		"blocked":     false,
		"exp":         time.Now().Add(time.Minute).Unix(),
	}).SignedString(secret)

	ref, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
	}).SignedString(secret)

	return acc, ref, nil
}

func validateRefresh(str string) (string, error) {
	token, err := jwt.Parse(str, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	emailVal, ok := claims["email"].(string)
	if !ok || emailVal == "" {
		return "", fmt.Errorf("invalid email claim")
	}
	return emailVal, nil
}

func generateDigits(n int) string {
	res := ""
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		res += num.String()
	}
	return res
}

func updateLoginState(tokenIn, status, accessToken, refreshToken string) {
	if tokenIn == "" {
		return
	}
	update := bson.M{"status": status}
	if accessToken != "" {
		update["access_token"] = accessToken
	}
	if refreshToken != "" {
		update["refresh_token"] = refreshToken
	}
	db.Collection("states").UpdateOne(context.TODO(), bson.M{"token_in": tokenIn}, bson.M{"$set": update})
}

func notifyMainBackend(accessToken string) {
	log.Println("[notifyMainBackend] CALLED")

	if accessToken == "" {
		log.Println("[notifyMainBackend] skip: empty token")
		return
	}

	baseURL := os.Getenv("MAIN_BACKEND_URL")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8000"
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/users/create_user"

	log.Println("[notifyMainBackend] POST", endpoint)

	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		log.Println("[notifyMainBackend] new request error:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("[notifyMainBackend] request error:", err)
		return
	}
	defer resp.Body.Close()

	log.Println("[notifyMainBackend] response:", resp.Status)
}

func getFrontendRedirectURL() string {
	if v := os.Getenv("FRONTEND_REDIRECT_URL"); v != "" {
		return v
	}
	return "http://localhost:5173"
}

func getFrontendRedirectURLWithTypeAndToken(t string, tokenIn string) string {
	base := strings.TrimRight(getFrontendRedirectURL(), "/")
	return fmt.Sprintf("%s/login?type=%s&token_in=%s",
		base,
		url.QueryEscape(t),
		url.QueryEscape(tokenIn),
	)
}
