package models

import (
	"time"
	"github.com/golang-jwt/jwt/v5"
)

// ===================== Response Types =====================
type ErrorResponse struct {
	Message string `json:"message"`
}

// ===================== Auth Models =====================
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	FirstName    *string   `json:"first_name"`
	LastName     *string   `json:"last_name"`
	PasswordHash string    `json:"-"` // ไม่ส่งไปใน JSON
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type RegisterRequest struct {
	Username  string  `json:"username" binding:"required"`
	Email     string  `json:"email" binding:"required,email"`
	Password  string  `json:"password" binding:"required,min=8"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
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

type UpdateProfileRequest struct {
	Username  *string `json:"username"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Password  *string `json:"password"`
}

// ===================== JWT Claims =====================
type CustomClaims struct {
	UserID   int      `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// ===================== Product Models =====================
type Product struct {
	ID          int            `json:"id"`
	CategoryID  *int           `json:"category_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Price       float64        `json:"price"`
	Stock       int            `json:"stock"`
	ImageURL    *string  		`json:"image_url"`
	IsActive    bool           `json:"is_active"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type ProductVariant struct {
	ID        int       `json:"id"`
	ProductID int       `json:"product_id"`
	Quantity  float64   `json:"quantity"`
	Price     float64   `json:"price"`
	Stock     int       `json:"stock"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Category struct {
	ID          int            `json:"id"`
	ParentID    *int           `json:"parent_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	ImageURL    *string  		`json:"image_url"`
	IsFeatured  bool           `json:"is_featured"`
	CreatedAt   time.Time      `json:"created_at"`
}

type UpdateProductRequest struct {
    CategoryID  *int    `json:"category_id"`
    Name        string  `json:"name"`
    Description string  `json:"description"`
    Price       float64 `json:"price"`
    Stock       int     `json:"stock"`
    ImageURL    *string `json:"image_url"`
    IsActive    bool    `json:"is_active"`
}

type CreateVariantRequest struct {
    Quantity float64 `json:"quantity" binding:"required,min=0"`
    Price    float64 `json:"price" binding:"required,min=0"`
    Stock    int     `json:"stock" binding:"min=0"`
    IsActive bool    `json:"is_active"`
}

type UpdateVariantRequest struct {
    Quantity *float64 `json:"quantity"`
    Price    *float64 `json:"price"`
    Stock    *int     `json:"stock"`
    IsActive *bool    `json:"is_active"`
}
