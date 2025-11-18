package handlers

import (
	"backend/auth"
	"backend/database"
	"backend/models"
	"database/sql"
	"log"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetMyProfileHandler godoc
// @Summary Get current user profile
// @Description Get the profile information of the currently authenticated user
// @Tags profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.UserInfo
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/profile [get]
func GetMyProfileHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	// ดึงข้อมูล user จาก database
	var user models.User
	query := `
		SELECT id, username, email, first_name, last_name, is_active, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	err := database.DB.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	} else if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	roles, err := database.GetUserRoles(userID.(int))
	if err != nil {
		log.Printf("Error getting roles: %v", err)
		roles = []string{}
	}

	type UserProfileResponse struct {
		ID        int      `json:"id"`
		Username  string   `json:"username"`
		Email     string   `json:"email"`
		FirstName *string  `json:"first_name"`
		LastName  *string  `json:"last_name"`
		Roles     []string `json:"roles"`
	}

	// ส่ง response
	c.JSON(200, UserProfileResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Roles:     roles,
	})
}

// GetProductsHandler godoc
// @Summary Get products
// @Description Get a list of products with optional filtering
// @Tags products
// @Accept json
// @Produce json
// @Param sort query string false "Sort order (price_asc, id_asc)" Enums(price_asc,id_asc)
// @Param max_price query number false "Maximum price filter"
// @Success 200 {object} object
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products [get]
func GetProductsHandler(c *gin.Context) {
	sort := c.Query("sort")
	maxPriceStr := c.Query("max_price")

	var maxPrice *float64
	if maxPriceStr != "" {
		if price, err := strconv.ParseFloat(maxPriceStr, 64); err == nil {
			maxPrice = &price
		}
	}

	products, err := database.GetProducts(sort, maxPrice)
	if err != nil {
		log.Printf("Error getting products: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"products": products})
}

// GetFeaturedCategoriesHandler godoc
// @Summary Get featured categories
// @Description Get a list of featured tea categories (subcategories of Tea Leaves)
// @Tags categories
// @Accept json
// @Produce json
// @Success 200 {object} object
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/categories/featured [get]
func GetFeaturedCategoriesHandler(c *gin.Context) {
	categories, err := database.GetFeaturedCategories()
	if err != nil {
		log.Printf("Error getting featured categories: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"categories": categories})
}

// GetFeaturedProductsHandler godoc
// @Summary Get featured products
// @Description Get random product recommendations
// @Tags products
// @Accept json
// @Produce json
// @Param limit query int false "Number of products to return (default 6)"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/featured [get]
func GetFeaturedProductsHandler(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "6")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		c.JSON(400, gin.H{"error": "invalid limit parameter"})
		return
	}

	// Cap the limit to prevent abuse
	if limit > 20 {
		limit = 20
	}

	products, err := database.GetFeaturedProducts(limit)
	if err != nil {
		log.Printf("Error getting featured products: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"products": products})
}

// CreateOrderHandler godoc
// @Summary Create a new order
// @Description Create a new order with products and shipping information
// @Tags orders
// @Accept json
// @Produce json
// @Param request body models.CreateOrderRequest true "Order creation data"
// @Security BearerAuth
// @Success 201 {object} models.Order
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/orders [post]
func CreateOrderHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	var req models.CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	order, err := database.CreateOrder(userID.(int), req, database.LogAudit, c)
	if err != nil {
		log.Printf("Error creating order: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, order)
}

// GetUserOrdersHandler godoc
// @Summary Get user's order history
// @Description Get the order history for the authenticated user
// @Tags orders
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/user/orders [get]
func GetUserOrdersHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	orders, err := database.GetUserOrders(userID.(int))
	if err != nil {
		log.Printf("Error getting user orders: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"orders": orders})
}

// GetOrderByIDHandler godoc
// @Summary Get order details by ID
// @Description Get detailed information for a specific order (user can only view their own orders)
// @Tags orders
// @Accept json
// @Produce json
// @Param id path int true "Order ID"
// @Security BearerAuth
// @Success 200 {object} models.Order
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/orders/{id} [get]
func GetOrderByIDHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid order id"})
		return
	}

	order, err := database.GetOrderByID(orderID, userID.(int))
	if err != nil {
		log.Printf("Error getting order by ID: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	if order == nil {
		c.JSON(404, gin.H{"error": "order not found"})
		return
	}

	c.JSON(200, order)
}

// GetCategoriesHandler godoc
// @Summary Get parent categories
// @Description Get a list of parent/main product categories (parent_id = null)
// @Tags categories
// @Accept json
// @Produce json
// @Success 200 {object} object
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/categories [get]
func GetCategoriesHandler(c *gin.Context) {
	categories, err := database.GetCategories()
	if err != nil {
		log.Printf("Error getting categories: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"categories": categories})
}

// GetProductByIDHandler godoc
// @Summary Get product by ID
// @Description Get a specific product by its ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{id} [get]
func GetProductByIDHandler(c *gin.Context) {
	productIDStr := c.Param("id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product id"})
		return
	}

	product, err := database.GetProductByID(productID)
	if err != nil {
		log.Printf("Error getting product by ID: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	if product == nil {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	c.JSON(200, gin.H{"product": product})
}

// UpdateProfileHandler godoc
// @Summary Update user profile
// @Description Update the profile information of the currently authenticated user
// @Tags profile
// @Accept json
// @Produce json
// @Param request body models.UpdateProfileRequest true "Profile update data"
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 409 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/profile [put]
func UpdateProfileHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check username uniqueness if provided
	if req.Username != nil {
		exists, err := database.CheckUsernameExists(*req.Username, userID.(int))
		if err != nil {
			log.Printf("Database error: %v", err)
			c.JSON(500, gin.H{"error": "internal server error"})
			return
		}
		if exists {
			c.JSON(409, gin.H{"error": "username already exists"})
			return
		}
	}

	var passwordHash *string
	if req.Password != nil {
		hashed, err := auth.HashPassword(*req.Password)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to hash password"})
			return
		}
		passwordHash = &hashed
	}

	err := database.UpdateUserProfile(userID.(int), req.FirstName, req.LastName, req.Username, passwordHash)
	if err != nil {
		log.Printf("Error updating profile: %v", err)
		c.JSON(500, gin.H{"error": "failed to update profile"})
		return
	}

	c.JSON(200, gin.H{"message": "profile updated successfully"})
}

// GetProductsByCategoryHandler godoc
// @Summary Get products by category
// @Description Get all products belonging to a specific category
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Category ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/categories/{id}/products [get]
func GetProductsByCategoryHandler(c *gin.Context) {
	categoryIDStr := c.Param("id")
	categoryID, err := strconv.Atoi(categoryIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid category id"})
		return
	}

	products, err := database.GetProductsByCategory(categoryID)
	if err != nil {
		log.Printf("Error getting products by category: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"products": products})
}