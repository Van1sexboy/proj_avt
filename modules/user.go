package modules

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User - структура пользователя в MongoDB
type User struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email         string             `bson:"email" json:"email"`
	FullName      string             `bson:"full_name" json:"full_name"`
	Roles         []string           `bson:"roles" json:"roles"`                   // например, ["Student"]
	RefreshTokens []string           `bson:"refresh_tokens" bson:"refresh_tokens"` // список активных токенов
}

// LoginState - та самая структура "Словарь" из сценария для отслеживания входа
type LoginState struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	TokenIn      string             `bson:"token_in"` // Ключ (State)
	Status       string             `bson:"status"`   // "pending", "granted", "declined"
	AccessToken  string             `bson:"access_token,omitempty"`
	RefreshToken string             `bson:"refresh_token,omitempty"`
	ExpiresAt    time.Time          `bson:"expires_at"` // Когда запись должна удалиться (через 5 мин)
}
