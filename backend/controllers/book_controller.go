package controllers

import (
	"backend/config"
	"backend/models"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ดูสินค้าทั้งหมด
func GetProducts(c *gin.Context) {
	rows, err := config.DB.Query("SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at FROM products")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		if err := rows.Scan(&p.ID, &p.CategoryID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.ImageURL, &p.IsActive, &p.CreatedAt, &p.UpdatedAt); err != nil {
			log.Println(err)
			continue
		}
		products = append(products, p)
	}

	c.JSON(http.StatusOK, products)
}

// ดูสินค้าชิ้นเดียว
func GetProductByID(c *gin.Context) {
	id := c.Param("id")
	pid, _ := strconv.Atoi(id)

	var p models.Product
	err := config.DB.QueryRow("SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at FROM products WHERE id=$1", pid).
		Scan(&p.ID, &p.CategoryID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.ImageURL, &p.IsActive, &p.CreatedAt, &p.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
		return
	}

	c.JSON(http.StatusOK, p)
}

// ดูหมวดหมู่ทั้งหมด
func GetCategories(c *gin.Context) {
	rows, err := config.DB.Query("SELECT id, parent_id, name, description, created_at FROM categories")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var categories []models.Category
	for rows.Next() {
		var cat models.Category
		if err := rows.Scan(&cat.ID, &cat.ParentID, &cat.Name, &cat.Description, &cat.CreatedAt); err != nil {
			log.Println(err)
			continue
		}
		categories = append(categories, cat)
	}

	c.JSON(http.StatusOK, categories)
}

// ดูสินค้าในหมวดหมู่
func GetProductsByCategory(c *gin.Context) {
	id := c.Param("id")
	catID, _ := strconv.Atoi(id)

	rows, err := config.DB.Query("SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at FROM products WHERE category_id=$1", catID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		if err := rows.Scan(&p.ID, &p.CategoryID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.ImageURL, &p.IsActive, &p.CreatedAt, &p.UpdatedAt); err != nil {
			log.Println(err)
			continue
		}
		products = append(products, p)
	}

	c.JSON(http.StatusOK, products)
}
