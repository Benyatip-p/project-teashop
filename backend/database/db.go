package database

import (
	"backend/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var DB *sql.DB

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func InitDB() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	var dbErr error

	host := getEnv("DB_HOST", "")
	name := getEnv("DB_NAME", "")
	user := getEnv("DB_USER", "")
	password := getEnv("DB_PASSWORD", "")
	port := getEnv("DB_PORT", "")

	conSt := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, name)
	// fmt.Println(conSt)
	DB, dbErr = sql.Open("postgres", conSt)
	if dbErr != nil {
		log.Fatal("failed to open database")
	}

	// กำหนดจำนวน Connection สูงสุด
	DB.SetMaxOpenConns(25)

	// กำหนดจำนวน Idle connection สูงสุด
	DB.SetMaxIdleConns(25)

	// กำหนดอายุของ Connection
	DB.SetConnMaxLifetime(5 * time.Minute)

	dbErr = DB.Ping()
	if dbErr != nil {
		log.Fatal("failed to connect to database", dbErr)
	}
	log.Println("successfully connected to database")
}

// ===================== Database Helper Functions =====================
func GetUserRoles(userID int) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func CheckUserPermission(userID int, permission string) bool {
	query := `
		SELECT COUNT(*)
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1 AND p.name = $2
	`

	var count int
	err := DB.QueryRow(query, userID, permission).Scan(&count)
	if err != nil {
		log.Printf("Error checking permission: %v", err)
		return false
	}

	return count > 0
}

func StoreRefreshToken(userID int, token string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := DB.Exec(query, userID, token, expiresAt)
	return err
}

func RevokeRefreshToken(token string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE token = $1 AND revoked_at IS NULL
	`
	_, err := DB.Exec(query, token)
	return err
}

func IsRefreshTokenValid(token string) (int, bool) {
	query := `
		SELECT user_id
		FROM refresh_tokens
		WHERE token = $1
		AND expires_at > NOW()
		AND revoked_at IS NULL
	`

	var userID int
	err := DB.QueryRow(query, token).Scan(&userID)
	if err != nil {
		return 0, false
	}

	return userID, true
}

func LogAudit(userID int, action, resource string, resourceID interface{}, details map[string]interface{}, c *gin.Context) {
	detailsJSON, _ := json.Marshal(details)

	query := `
		INSERT INTO audit_logs
		(user_id, action, resource, resource_id, details, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	var resourceIDStr string
	if resourceID != nil {
		resourceIDStr = fmt.Sprintf("%v", resourceID)
	}

	DB.Exec(query,
		userID,
		action,
		resource,
		resourceIDStr,
		detailsJSON,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
	)
}

// ===================== Product Database Functions =====================
func GetProducts(sort string, maxPrice *float64) ([]models.Product, error) {
	var args []interface{}

	baseQuery := `
		SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at
		FROM products
		WHERE is_active = true
	`

	// Add max_price filter if provided
	if maxPrice != nil {
		baseQuery += " AND price <= $1"
		args = append(args, *maxPrice)
	}

	// Add sorting
	if sort == "price_asc" {
		baseQuery += " ORDER BY price ASC"
	} else if sort == "id_asc" {
		baseQuery += " ORDER BY id ASC"
	} else {
		baseQuery += " ORDER BY id ASC" // Default to ID ascending
	}

	rows, err := DB.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var product models.Product
		err := rows.Scan(
			&product.ID,
			&product.CategoryID,
			&product.Name,
			&product.Description,
			&product.Price,
			&product.Stock,
			&product.ImageURL,
			&product.IsActive,
			&product.CreatedAt,
			&product.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	return products, nil
}

// ===================== Order Database Functions =====================
func CreateOrder(userID int, req models.CreateOrderRequest, logAudit func(int, string, string, interface{}, map[string]interface{}, *gin.Context), c *gin.Context) (*models.Order, error) {
	// Start transaction
	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Calculate total amount and validate products
	var totalAmount float64
	orderItems := make([]models.OrderItem, 0, len(req.Items))

	for _, item := range req.Items {
		// Get product details
		var product models.Product
		err := tx.QueryRow(`
			SELECT id, name, price, stock, is_active
			FROM products
			WHERE id = $1 AND is_active = true
		`, item.ProductID).Scan(&product.ID, &product.Name, &product.Price, &product.Stock, &product.IsActive)

		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("product with ID %d not found", item.ProductID)
		}
		if err != nil {
			return nil, err
		}

		if product.Stock < item.Quantity {
			return nil, fmt.Errorf("insufficient stock for product %s", product.Name)
		}

		itemTotal := product.Price * float64(item.Quantity)
		totalAmount += itemTotal

		orderItems = append(orderItems, models.OrderItem{
			ProductID:    product.ID,
			ProductName:  product.Name,
			Quantity:     item.Quantity,
			PricePerUnit: product.Price,
			TotalPrice:   itemTotal,
		})
	}

	// Create order
	var orderID int
	err = tx.QueryRow(`
		INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address)
		VALUES ($1, $2, 'pending', $3, $4)
		RETURNING id
	`, userID, totalAmount, req.CustomerName, req.ShippingAddress).Scan(&orderID)

	if err != nil {
		return nil, err
	}

	// Insert order items
	for i, item := range orderItems {
		var itemID int
		err = tx.QueryRow(`
			INSERT INTO order_items (order_id, product_id, quantity, price_per_unit)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, orderID, item.ProductID, item.Quantity, item.PricePerUnit).Scan(&itemID)

		if err != nil {
			return nil, err
		}

		orderItems[i].ID = itemID

		// Update product stock
		_, err = tx.Exec(`
			UPDATE products
			SET stock = stock - $1
			WHERE id = $2
		`, item.Quantity, item.ProductID)

		if err != nil {
			return nil, err
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	// Log audit
	logAudit(userID, "create", "orders", orderID, map[string]interface{}{
		"total_amount": totalAmount,
		"item_count":   len(orderItems),
	}, c)

	// Return created order
	order := &models.Order{
		ID:              orderID,
		UserID:          userID,
		TotalAmount:     totalAmount,
		Status:          "pending",
		CustomerName:    req.CustomerName,
		ShippingAddress: req.ShippingAddress,
		Items:           orderItems,
		CreatedAt:       time.Now(),
	}

	return order, nil
}

func GetUserOrders(userID int) ([]models.Order, error) {
	// Get orders
	rows, err := DB.Query(`
		SELECT id, user_id, total_amount, status, customer_name, shipping_address, created_at
		FROM orders
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orders []models.Order
	for rows.Next() {
		var order models.Order
		err := rows.Scan(
			&order.ID,
			&order.UserID,
			&order.TotalAmount,
			&order.Status,
			&order.CustomerName,
			&order.ShippingAddress,
			&order.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Get order items
		itemRows, err := DB.Query(`
			SELECT oi.id, oi.product_id, p.name, oi.quantity, oi.price_per_unit
			FROM order_items oi
			JOIN products p ON oi.product_id = p.id
			WHERE oi.order_id = $1
		`, order.ID)

		if err != nil {
			return nil, err
		}

		var items []models.OrderItem
		for itemRows.Next() {
			var item models.OrderItem
			err := itemRows.Scan(
				&item.ID,
				&item.ProductID,
				&item.ProductName,
				&item.Quantity,
				&item.PricePerUnit,
			)
			if err != nil {
				itemRows.Close()
				return nil, err
			}
			item.TotalPrice = item.PricePerUnit * float64(item.Quantity)
			items = append(items, item)
		}
		itemRows.Close()

		order.Items = items
		orders = append(orders, order)
	}

	return orders, nil
}

func GetOrderByID(orderID, userID int) (*models.Order, error) {
	// Get order and verify ownership
	var order models.Order
	err := DB.QueryRow(`
		SELECT id, user_id, total_amount, status, customer_name, shipping_address, created_at
		FROM orders
		WHERE id = $1 AND user_id = $2
	`, orderID, userID).Scan(
		&order.ID,
		&order.UserID,
		&order.TotalAmount,
		&order.Status,
		&order.CustomerName,
		&order.ShippingAddress,
		&order.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Order not found or doesn't belong to user
	}
	if err != nil {
		return nil, err
	}

	// Get order items
	itemRows, err := DB.Query(`
		SELECT oi.id, oi.product_id, p.name, oi.quantity, oi.price_per_unit
		FROM order_items oi
		JOIN products p ON oi.product_id = p.id
		WHERE oi.order_id = $1
	`, orderID)

	if err != nil {
		return nil, err
	}
	defer itemRows.Close()

	var items []models.OrderItem
	for itemRows.Next() {
		var item models.OrderItem
		err := itemRows.Scan(
			&item.ID,
			&item.ProductID,
			&item.ProductName,
			&item.Quantity,
			&item.PricePerUnit,
		)
		if err != nil {
			return nil, err
		}
		item.TotalPrice = item.PricePerUnit * float64(item.Quantity)
		items = append(items, item)
	}

	order.Items = items
	return &order, nil
}

func GetFeaturedProducts(limit int) ([]models.Product, error) {
	query := `
		SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at
		FROM products
		WHERE is_active = true
		ORDER BY RANDOM()
		LIMIT $1
	`

	rows, err := DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var product models.Product
		err := rows.Scan(
			&product.ID,
			&product.CategoryID,
			&product.Name,
			&product.Description,
			&product.Price,
			&product.Stock,
			&product.ImageURL,
			&product.IsActive,
			&product.CreatedAt,
			&product.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	return products, nil
}

func GetFeaturedCategories() ([]models.Category, error) {
	query := `
		SELECT id, parent_id, name, description, image_url, is_featured, created_at
		FROM categories
		WHERE parent_id = 1
		ORDER BY created_at ASC
	`

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []models.Category
	for rows.Next() {
		var category models.Category
		err := rows.Scan(
			&category.ID,
			&category.ParentID,
			&category.Name,
			&category.Description,
			&category.ImageURL,
			&category.IsFeatured,
			&category.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, nil
}

func GetCategories() ([]models.Category, error) {
	query := `
		SELECT id, parent_id, name, description, image_url, is_featured, created_at
		FROM categories
		WHERE parent_id IS NULL
		ORDER BY created_at ASC
	`

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []models.Category
	for rows.Next() {
		var category models.Category
		err := rows.Scan(
			&category.ID,
			&category.ParentID,
			&category.Name,
			&category.Description,
			&category.ImageURL,
			&category.IsFeatured,
			&category.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, nil
}

func GetProductByID(productID int) (*models.Product, error) {
	query := `
		SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at
		FROM products
		WHERE id = $1 AND is_active = true
	`

	var product models.Product
	err := DB.QueryRow(query, productID).Scan(
		&product.ID,
		&product.CategoryID,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.ImageURL,
		&product.IsActive,
		&product.CreatedAt,
		&product.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Product not found
	}
	if err != nil {
		return nil, err
	}

	return &product, nil
}

func CheckUsernameExists(username string, excludeUserID int) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE username = $1 AND id != $2`
	var count int
	err := DB.QueryRow(query, username, excludeUserID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func UpdateUserProfile(userID int, firstName, lastName, username, passwordHash *string) error {
	query := "UPDATE users SET updated_at = NOW()"
	args := []interface{}{}
	argID := 1

	if firstName != nil {
		query += fmt.Sprintf(", first_name = $%d", argID)
		args = append(args, *firstName)
		argID++
	}
	if lastName != nil {
		query += fmt.Sprintf(", last_name = $%d", argID)
		args = append(args, *lastName)
		argID++
	}
	if username != nil {
		query += fmt.Sprintf(", username = $%d", argID)
		args = append(args, *username)
		argID++
	}
	if passwordHash != nil {
		query += fmt.Sprintf(", password_hash = $%d", argID)
		args = append(args, *passwordHash)
		argID++
	}

	// ถ้าไม่มีอะไรส่งมาให้อัปเดตเลย
	if len(args) == 0 {
		return nil
	}

	query += fmt.Sprintf(" WHERE id = $%d", argID)
	args = append(args, userID)

	_, err := DB.Exec(query, args...)
	return err
}

func GetProductsByCategory(categoryID int) ([]models.Product, error) {
	query := `
		SELECT id, category_id, name, description, price, stock, image_url, is_active, created_at, updated_at
		FROM products
		WHERE category_id = $1 AND is_active = true
		ORDER BY created_at DESC
	`

	rows, err := DB.Query(query, categoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var product models.Product
		err := rows.Scan(
			&product.ID,
			&product.CategoryID,
			&product.Name,
			&product.Description,
			&product.Price,
			&product.Stock,
			&product.ImageURL,
			&product.IsActive,
			&product.CreatedAt,
			&product.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	return products, nil
}