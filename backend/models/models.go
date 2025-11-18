package models

import (
	"time"
	"database/sql"
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
	ImageURL    sql.NullString `json:"image_url"`
	IsActive    bool           `json:"is_active"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ===================== Category Models =====================
type Category struct {
	ID          int            `json:"id"`
	ParentID    *int           `json:"parent_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	ImageURL    sql.NullString `json:"image_url"`
	IsFeatured  bool           `json:"is_featured"`
	CreatedAt   time.Time      `json:"created_at"`
}

// ===================== Order Models =====================
type OrderItemRequest struct {
	ProductID int `json:"product_id" binding:"required"`
	Quantity  int `json:"quantity" binding:"required,min=1"`
}

type CreateOrderRequest struct {
	CustomerName    string             `json:"customer_name" binding:"required"`
	ShippingAddress string             `json:"shipping_address" binding:"required"`
	Items           []OrderItemRequest `json:"items" binding:"required,min=1"`
}

type OrderItem struct {
	ID           int     `json:"id"`
	ProductID    int     `json:"product_id"`
	ProductName  string  `json:"product_name"`
	Quantity     int     `json:"quantity"`
	PricePerUnit float64 `json:"price_per_unit"`
	TotalPrice   float64 `json:"total_price"`
}

type Order struct {
	ID              int         `json:"id"`
	UserID          int         `json:"user_id"`
	TotalAmount     float64     `json:"total_amount"`
	Status          string      `json:"status"`
	CustomerName    string      `json:"customer_name"`
	ShippingAddress string      `json:"shipping_address"`
	Items           []OrderItem `json:"items"`
	CreatedAt       time.Time   `json:"created_at"`
}
