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

// ===================== Address Database Functions =====================
func GetAddressesByUserID(userID int) ([]models.Address, error) {
	query := `
		SELECT id, user_id, recipient_name, phone_number, address, province, postal_code, is_default
		FROM addresses
		WHERE user_id = $1
		ORDER BY is_default DESC, id ASC
	`

	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addresses []models.Address
	for rows.Next() {
		var address models.Address
		err := rows.Scan(
			&address.ID,
			&address.UserID,
			&address.RecipientName,
			&address.PhoneNumber,
			&address.Address,
			&address.Province,
			&address.PostalCode,
			&address.IsDefault,
		)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}

	return addresses, nil
}

func GetDefaultAddressByUserID(userID int) (*models.Address, error) {
	query := `
		SELECT id, user_id, recipient_name, phone_number, address, province, postal_code, is_default
		FROM addresses
		WHERE user_id = $1 AND is_default = true
		LIMIT 1
	`

	var address models.Address
	err := DB.QueryRow(query, userID).Scan(
		&address.ID,
		&address.UserID,
		&address.RecipientName,
		&address.PhoneNumber,
		&address.Address,
		&address.Province,
		&address.PostalCode,
		&address.IsDefault,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &address, nil
}

func CountAddressesByUserID(userID int) (int, error) {
	query := `SELECT COUNT(*) FROM addresses WHERE user_id = $1`
	var count int
	err := DB.QueryRow(query, userID).Scan(&count)
	return count, err
}

func UnsetDefaultAddresses(userID int) error {
	query := `UPDATE addresses SET is_default = false WHERE user_id = $1`
	_, err := DB.Exec(query, userID)
	return err
}

func CreateAddress(userID int, recipientName, phoneNumber, address, province, postalCode string, isDefault bool) (int, error) {
	query := `
		INSERT INTO addresses (user_id, recipient_name, phone_number, address, province, postal_code, is_default)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`

	var newID int
	err := DB.QueryRow(query, userID, recipientName, phoneNumber, address, province, postalCode, isDefault).Scan(&newID)
	if err != nil {
		return 0, err
	}

	return newID, nil
}

func GetAddressOwner(addressID int) (int, error) {
	query := `SELECT user_id FROM addresses WHERE id = $1`
	var userID int
	err := DB.QueryRow(query, addressID).Scan(&userID)
	return userID, err
}

func UpdateAddress(addressID int, recipientName, phoneNumber, address, province, postalCode *string, isDefault *bool) error {
	query := "UPDATE addresses SET"
	args := []interface{}{}
	argID := 1
	updates := []string{}

	if recipientName != nil {
		updates = append(updates, fmt.Sprintf("recipient_name = $%d", argID))
		args = append(args, *recipientName)
		argID++
	}
	if phoneNumber != nil {
		updates = append(updates, fmt.Sprintf("phone_number = $%d", argID))
		args = append(args, *phoneNumber)
		argID++
	}
	if address != nil {
		updates = append(updates, fmt.Sprintf("address = $%d", argID))
		args = append(args, *address)
		argID++
	}
	if province != nil {
		updates = append(updates, fmt.Sprintf("province = $%d", argID))
		args = append(args, *province)
		argID++
	}
	if postalCode != nil {
		updates = append(updates, fmt.Sprintf("postal_code = $%d", argID))
		args = append(args, *postalCode)
		argID++
	}
	if isDefault != nil {
		updates = append(updates, fmt.Sprintf("is_default = $%d", argID))
		args = append(args, *isDefault)
		argID++
	}

	if len(updates) == 0 {
		return nil
	}

	query += " " + updates[0]
	for i := 1; i < len(updates); i++ {
		query += ", " + updates[i]
	}
	query += fmt.Sprintf(" WHERE id = $%d", argID)
	args = append(args, addressID)

	_, err := DB.Exec(query, args...)
	return err
}

func DeleteAddress(addressID int) error {
	query := "DELETE FROM addresses WHERE id = $1"
	_, err := DB.Exec(query, addressID)
	return err
}

func GetVariantsByProductID(productID int) ([]models.ProductVariant, error) {
	query := `
		SELECT id, product_id, quantity, price, stock, is_active, created_at, updated_at
		FROM product_variants
		WHERE product_id = $1 AND is_active = true
		ORDER BY quantity ASC
	`

	rows, err := DB.Query(query, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var variants []models.ProductVariant
	for rows.Next() {
		var variant models.ProductVariant
		err := rows.Scan(
			&variant.ID,
			&variant.ProductID,
			&variant.Quantity,
			&variant.Price,
			&variant.Stock,
			&variant.IsActive,
			&variant.CreatedAt,
			&variant.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		variants = append(variants, variant)
	}

	return variants, nil
}

func CreateVariant(productID int, quantity float64, price float64, stock int, isActive bool) (int, error) {
	query := `
		INSERT INTO product_variants (product_id, quantity, price, stock, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING id
	`

	var newID int
	err := DB.QueryRow(query, productID, quantity, price, stock, isActive).Scan(&newID)
	if err != nil {
		return 0, err
	}

	return newID, nil
}

func UpdateVariant(variantID int, quantity *float64, price *float64, stock *int, isActive *bool) error {
	query := "UPDATE product_variants SET updated_at = NOW()"
	args := []interface{}{}
	argID := 1

	if quantity != nil {
		query += fmt.Sprintf(", quantity = $%d", argID)
		args = append(args, *quantity)
		argID++
	}
	if price != nil {
		query += fmt.Sprintf(", price = $%d", argID)
		args = append(args, *price)
		argID++
	}
	if stock != nil {
		query += fmt.Sprintf(", stock = $%d", argID)
		args = append(args, *stock)
		argID++
	}
	if isActive != nil {
		query += fmt.Sprintf(", is_active = $%d", argID)
		args = append(args, *isActive)
		argID++
	}

	if len(args) == 0 {
		return nil
	}

	query += fmt.Sprintf(" WHERE id = $%d", argID)
	args = append(args, variantID)

	_, err := DB.Exec(query, args...)
	return err
}

func DeleteVariant(variantID int) error {
	query := "DELETE FROM product_variants WHERE id = $1"
	_, err := DB.Exec(query, variantID)
	return err
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