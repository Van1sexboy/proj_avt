package modules

type GitHubTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type GitHubUserResponse struct {
	Email string `json:"email"`
	Login string `json:"login"`
}

// Яндекс на будущее
type YandexTokenResponse struct {
	AccessToken string `json:"access_token"`
}
