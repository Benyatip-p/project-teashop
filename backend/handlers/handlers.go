package handlers

import (
	"backend/auth"
	"backend/database"
	"backend/models"
	"database/sql"
	"log"
	"strconv"
	"time"

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

	// Add average rating to each product
	type ProductWithRating struct {
		models.Product
		AvgRating float64 `json:"avg_rating"`
	}

	productsWithRating := make([]ProductWithRating, len(products))
	for i, product := range products {
		avgRating, err := database.GetAverageRatingByProductID(product.ID)
		if err != nil {
			log.Printf("Error getting average rating for product %d: %v", product.ID, err)
			avgRating = 0
		}
		productsWithRating[i] = ProductWithRating{
			Product:   product,
			AvgRating: avgRating,
		}
	}

	c.JSON(200, gin.H{"products": productsWithRating})
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
// @Param pid path int true "Product ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{pid} [get]
func GetProductByIDHandler(c *gin.Context) {
	productIDStr := c.Param("pid")
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

	// Get variants for this product
	variants, err := database.GetVariantsByProductID(productID)
	if err != nil {
		log.Printf("Error getting variants: %v", err)
		variants = []models.ProductVariant{}
	}

	// Get average rating
	avgRating, err := database.GetAverageRatingByProductID(productID)
	if err != nil {
		log.Printf("Error getting average rating: %v", err)
		avgRating = 0
	}

	response := gin.H{
		"product":     product,
		"variants":    variants,
		"avg_rating":  avgRating,
	}

	c.JSON(200, response)
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

// CreateProductHandler godoc
// @Summary Create a new product
// @Description Add a new product to the database
// @Tags products
// @Accept json
// @Produce json
// @Param request body models.Product true "Product data"
// @Success 201 {object} models.Product
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products [post]
func CreateProductHandler(c *gin.Context) {
	var input models.Product
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	query := `INSERT INTO products (category_id, name, description, price, stock, image_url, is_active, created_at, updated_at)
	          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW()) RETURNING id`

	var newID int
	err := database.DB.QueryRow(query, input.CategoryID, input.Name, input.Description, input.Price, input.Stock, input.ImageURL, input.IsActive).Scan(&newID)
	if err != nil {
		log.Printf("Error creating product: %v", err)
		c.JSON(500, gin.H{"error": "failed to create product"})
		return
	}

	input.ID = newID
	c.JSON(201, input)
}
// UpdateProductHandler godoc
// @Summary Update a product
// @Description Update an existing product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param request body models.Product true "Updated product data"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{id} [put]
func UpdateProductHandler(c *gin.Context) {
    idStr := c.Param("id")
    pid, err := strconv.Atoi(idStr)
    if err != nil {
        c.JSON(400, gin.H{"error": "invalid product ID"})
        return
    }

    var req models.UpdateProductRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // แปลง ImageURL เป็น sql.NullString
    var img sql.NullString
    if req.ImageURL != nil && *req.ImageURL != "" {
        img = sql.NullString{String: *req.ImageURL, Valid: true}
    } else {
        img = sql.NullString{Valid: false}
    }

    query := `UPDATE products 
              SET category_id=$1, name=$2, description=$3, price=$4, stock=$5, image_url=$6, is_active=$7, updated_at=NOW()
              WHERE id=$8`

    res, err := database.DB.Exec(query, req.CategoryID, req.Name, req.Description, req.Price, req.Stock, img, req.IsActive, pid)
    if err != nil {
        log.Printf("Error updating product: %v", err)
        c.JSON(500, gin.H{"error": "failed to update product"})
        return
    }

    rowsAffected, _ := res.RowsAffected()
    if rowsAffected == 0 {
        c.JSON(404, gin.H{"error": "product not found"})
        return
    }

    c.JSON(200, gin.H{"message": "product updated successfully"})
}


// DeleteProductHandler godoc
// @Summary Delete a product
// @Description Delete a product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{id} [delete]
func DeleteProductHandler(c *gin.Context) {
	idStr := c.Param("id")
	pid, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product ID"})
		return
	}

	res, err := database.DB.Exec("DELETE FROM products WHERE id=$1", pid)
	if err != nil {
		log.Printf("Error deleting product: %v", err)
		c.JSON(500, gin.H{"error": "failed to delete product"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	c.JSON(200, gin.H{"message": "product deleted successfully"})
}

// GetVariantsByProductHandler godoc
// @Summary Get variants for a product
// @Description Get all active variants for a specific product
// @Tags variants
// @Accept json
// @Produce json
// @Param product_id path int true "Product ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/variants/product/{product_id} [get]
func GetVariantsByProductHandler(c *gin.Context) {
	productIDStr := c.Param("product_id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product id"})
		return
	}

	variants, err := database.GetVariantsByProductID(productID)
	if err != nil {
		log.Printf("Error getting variants: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"variants": variants})
}

// CreateVariantHandler godoc
// @Summary Create a new variant
// @Description Add a new variant for a product
// @Tags variants
// @Accept json
// @Produce json
// @Param product_id path int true "Product ID"
// @Param request body models.CreateVariantRequest true "Variant data"
// @Success 201 {object} models.ProductVariant
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/variants/product/{product_id} [post]
func CreateVariantHandler(c *gin.Context) {
	productIDStr := c.Param("product_id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product id"})
		return
	}

	var req models.CreateVariantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	newID, err := database.CreateVariant(productID, req.Quantity, req.Price, req.Stock, req.IsActive)
	if err != nil {
		log.Printf("Error creating variant: %v", err)
		c.JSON(500, gin.H{"error": "failed to create variant"})
		return
	}

	variant := models.ProductVariant{
		ID:        newID,
		ProductID: productID,
		Quantity:  req.Quantity,
		Price:     req.Price,
		Stock:     req.Stock,
		IsActive:  req.IsActive,
	}

	c.JSON(201, variant)
}

// UpdateVariantHandler godoc
// @Summary Update a variant
// @Description Update an existing variant by ID
// @Tags variants
// @Accept json
// @Produce json
// @Param id path int true "Variant ID"
// @Param request body models.UpdateVariantRequest true "Updated variant data"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/variants/{id} [put]
func UpdateVariantHandler(c *gin.Context) {
	variantIDStr := c.Param("id")
	variantID, err := strconv.Atoi(variantIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid variant id"})
		return
	}

	var req models.UpdateVariantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	err = database.UpdateVariant(variantID, req.Quantity, req.Price, req.Stock, req.IsActive)
	if err != nil {
		log.Printf("Error updating variant: %v", err)
		c.JSON(500, gin.H{"error": "failed to update variant"})
		return
	}

	c.JSON(200, gin.H{"message": "variant updated successfully"})
}

// DeleteVariantHandler godoc
// @Summary Delete a variant
// @Description Delete a variant by ID
// @Tags variants
// @Accept json
// @Produce json
// @Param id path int true "Variant ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/variants/{id} [delete]
func DeleteVariantHandler(c *gin.Context) {
	variantIDStr := c.Param("id")
	variantID, err := strconv.Atoi(variantIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid variant id"})
		return
	}

	err = database.DeleteVariant(variantID)
	if err != nil {
		log.Printf("Error deleting variant: %v", err)
		c.JSON(500, gin.H{"error": "failed to delete variant"})
		return
	}

	c.JSON(200, gin.H{"message": "variant deleted successfully"})
}

// GetAddressesHandler godoc
// @Summary Get user addresses
// @Description Get all addresses for the authenticated user
// @Tags addresses
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/addresses [get]
func GetAddressesHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	addresses, err := database.GetAddressesByUserID(userID.(int))
	if err != nil {
		log.Printf("Error getting addresses: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"addresses": addresses})
}

// GetDefaultAddressHandler godoc
// @Summary Get default address
// @Description Get the default address for the authenticated user
// @Tags addresses
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.Address
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/addresses/default [get]
func GetDefaultAddressHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	address, err := database.GetDefaultAddressByUserID(userID.(int))
	if err != nil {
		log.Printf("Error getting default address: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	if address == nil {
		c.JSON(404, gin.H{"error": "no default address found"})
		return
	}

	c.JSON(200, address)
}

// CreateAddressHandler godoc
// @Summary Create a new address
// @Description Add a new address for the authenticated user (max 2 addresses)
// @Tags addresses
// @Accept json
// @Produce json
// @Param request body models.CreateAddressRequest true "Address data"
// @Security BearerAuth
// @Success 201 {object} models.Address
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 409 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/addresses [post]
func CreateAddressHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	var req models.CreateAddressRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check max 2 addresses
	count, err := database.CountAddressesByUserID(userID.(int))
	if err != nil {
		log.Printf("Error counting addresses: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	if count >= 2 {
		c.JSON(409, gin.H{"error": "maximum 2 addresses allowed per user"})
		return
	}

	// If setting as default, unset others
	if req.IsDefault {
		err = database.UnsetDefaultAddresses(userID.(int))
		if err != nil {
			log.Printf("Error unsetting default addresses: %v", err)
			c.JSON(500, gin.H{"error": "internal server error"})
			return
		}
	}

	newID, err := database.CreateAddress(userID.(int), req.RecipientName, req.PhoneNumber, req.Address, req.Province, req.PostalCode, req.IsDefault)
	if err != nil {
		log.Printf("Error creating address: %v", err)
		c.JSON(500, gin.H{"error": "failed to create address"})
		return
	}

	address := models.Address{
		ID:            newID,
		UserID:        userID.(int),
		RecipientName: req.RecipientName,
		PhoneNumber:   req.PhoneNumber,
		Address:       req.Address,
		Province:      req.Province,
		PostalCode:    req.PostalCode,
		IsDefault:     req.IsDefault,
	}

	c.JSON(201, address)
}

// UpdateAddressHandler godoc
// @Summary Update an address
// @Description Update an existing address by ID
// @Tags addresses
// @Accept json
// @Produce json
// @Param id path int true "Address ID"
// @Param request body models.UpdateAddressRequest true "Updated address data"
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/addresses/{id} [put]
func UpdateAddressHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	addressIDStr := c.Param("id")
	addressID, err := strconv.Atoi(addressIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid address id"})
		return
	}

	var req models.UpdateAddressRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check ownership
	ownerID, err := database.GetAddressOwner(addressID)
	if err != nil {
		log.Printf("Error getting address owner: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	if ownerID != userID.(int) {
		c.JSON(403, gin.H{"error": "access denied"})
		return
	}

	// If setting as default, unset others
	if req.IsDefault != nil && *req.IsDefault {
		err = database.UnsetDefaultAddresses(userID.(int))
		if err != nil {
			log.Printf("Error unsetting default addresses: %v", err)
			c.JSON(500, gin.H{"error": "internal server error"})
			return
		}
	}

	err = database.UpdateAddress(addressID, req.RecipientName, req.PhoneNumber, req.Address, req.Province, req.PostalCode, req.IsDefault)
	if err != nil {
		log.Printf("Error updating address: %v", err)
		c.JSON(500, gin.H{"error": "failed to update address"})
		return
	}

	c.JSON(200, gin.H{"message": "address updated successfully"})
}

// DeleteAddressHandler godoc
// @Summary Delete an address
// @Description Delete an address by ID
// @Tags addresses
// @Accept json
// @Produce json
// @Param id path int true "Address ID"
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/addresses/{id} [delete]
func DeleteAddressHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	addressIDStr := c.Param("id")
	addressID, err := strconv.Atoi(addressIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid address id"})
		return
	}

	// Check ownership
	ownerID, err := database.GetAddressOwner(addressID)
	if err != nil {
		log.Printf("Error getting address owner: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	if ownerID != userID.(int) {
		c.JSON(403, gin.H{"error": "access denied"})
		return
	}

	err = database.DeleteAddress(addressID)
	if err != nil {
		log.Printf("Error deleting address: %v", err)
		c.JSON(500, gin.H{"error": "failed to delete address"})
		return
	}

	c.JSON(200, gin.H{"message": "address deleted successfully"})
}

// CreateReviewHandler godoc
// @Summary Create a new review
// @Description Add a new review for a product by the authenticated user
// @Tags reviews
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param request body models.CreateReviewRequest true "Review data"
// @Security BearerAuth
// @Success 201 {object} models.Review
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{id}/reviews [post]
func CreateReviewHandler(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	productIDStr := c.Param("id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product id"})
		return
	}

	// Check if product exists
	product, err := database.GetProductByID(productID)
	if err != nil {
		log.Printf("Error getting product: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	if product == nil {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	var req models.CreateReviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	newID, err := database.CreateReview(productID, userID.(int), req.Rating)
	if err != nil {
		log.Printf("Error creating review: %v", err)
		c.JSON(500, gin.H{"error": "failed to create review"})
		return
	}

	review := models.Review{
		ID:        newID,
		ProductID: productID,
		UserID:    userID.(int),
		Rating:    req.Rating,
		CreatedAt: time.Now(), // Approximate, since we don't fetch from DB
	}

	c.JSON(201, review)
}

// GetProductReviewsHandler godoc
// @Summary Get reviews for a product
// @Description Get all reviews for a specific product
// @Tags reviews
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} object
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/products/{id}/reviews [get]
func GetProductReviewsHandler(c *gin.Context) {
	productIDStr := c.Param("id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid product id"})
		return
	}

	// Check if product exists
	product, err := database.GetProductByID(productID)
	if err != nil {
		log.Printf("Error getting product: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	if product == nil {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	reviews, err := database.GetReviewsByProductID(productID)
	if err != nil {
		log.Printf("Error getting reviews: %v", err)
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	avgRating, err := database.GetAverageRatingByProductID(productID)
	if err != nil {
		log.Printf("Error getting average rating: %v", err)
		avgRating = 0
	}

	response := gin.H{
		"reviews":     reviews,
		"avg_rating":  avgRating,
		"total_count": len(reviews),
	}

	c.JSON(200, response)
}
