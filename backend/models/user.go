package models

import "time"

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	FirstName    *string   `json:"first_name"`
	LastName     *string   `json:"last_name"`
	PasswordHash string    `json:"-"` // ไม่ส่งกลับ client
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	ID        int      `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName *string  `json:"first_name"`
	LastName  *string  `json:"last_name"`
	Roles     []string `json:"roles"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
