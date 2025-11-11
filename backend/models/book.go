package models

import "time"

type Product struct {
	ID         int       `json:"id"`
	CategoryID int       `json:"category_id"`
	Name       string    `json:"name"`
	Description string   `json:"description"`
	Price      float64   `json:"price"`
	Stock      int       `json:"stock"`
	ImageURL   string    `json:"image_url"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Category struct {
	ID        int       `json:"id"`
	ParentID  *int      `json:"parent_id"` // ใช้ *int เพราะ parent_id อาจเป็น NULL
	Name      string    `json:"name"`
	Description string  `json:"description"`
	CreatedAt time.Time `json:"created_at"`
}