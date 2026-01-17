package modules

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User - структура пользователя в MongoDB
type User struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID        int                `bson:"user_id" json:"user_id"`
	Username      string             `bson:"username" json:"username"`
	Email         string             `bson:"email" json:"email"`
	FullName      string             `bson:"full_name" json:"full_name"`
	Roles         []string           `bson:"roles" json:"roles"`
	Permissions   []string           `bson:"permissions" json:"permissions"`
	RefreshTokens []string           `bson:"refresh_tokens" json:"refresh_tokens"`
}

// LoginState - состояние авторизации
type LoginState struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	TokenIn      string             `bson:"token_in"`
	Status       string             `bson:"status"`
	AccessToken  string             `bson:"access_token,omitempty"`
	RefreshToken string             `bson:"refresh_token,omitempty"`
	ExpiresAt    time.Time          `bson:"expires_at"` // ✅ ВАЖНО
}
