package auth

import (
	"backend/database"
	"backend/models"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(getEnv("JWT_SECRET", "your-secret-key"))

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateAccessToken(userID int, username string, roles []string) (string, error) {
	claims := models.CustomClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // 15 minutes
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func generateRefreshToken() (string, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Register handles user registration
// @Summary Register a new user
// @Description Register a new user with username, email, and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "Registration data"
// @Success 201 {object} models.User
// @Failure 400 {object} models.ErrorResponse
// @Failure 409 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/register [post]
func Register(db *sql.DB, logAudit func(int, string, string, interface{}, map[string]interface{}, *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request data"})
			return
		}

		// Check if username exists
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", req.Username).Scan(&count)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Database error"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusConflict, models.ErrorResponse{Message: "Username already exists"})
			return
		}

		// Check if email exists
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", req.Email).Scan(&count)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Database error"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusConflict, models.ErrorResponse{Message: "Email already exists"})
			return
		}

		// Hash password
		hashedPassword, err := HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to hash password"})
			return
		}

		// Insert user
		var userID int
		err = db.QueryRow(`
			INSERT INTO users (username, email, first_name, last_name, password_hash, is_active, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
			RETURNING id
		`, req.Username, req.Email, req.FirstName, req.LastName, hashedPassword).Scan(&userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to create user"})
			return
		}

		// Assign default role 'user'
		_, err = db.Exec("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'user'", userID)
		if err != nil {
			// Log error but don't fail registration
			fmt.Printf("Failed to assign default role: %v\n", err)
		}

		// Get created user
		var user models.User
		err = db.QueryRow(`
			SELECT id, username, email, first_name, last_name, is_active, created_at, updated_at
			FROM users WHERE id = $1
		`, userID).Scan(&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve user"})
			return
		}

		// Log audit
		logAudit(userID, "register", "users", userID, map[string]interface{}{
			"username": req.Username,
			"email":    req.Email,
		}, c)

		c.JSON(http.StatusCreated, user)
	}
}

// Login handles user login
// @Summary Login user
// @Description Authenticate user and return access/refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/login [post]
func Login(db *sql.DB, logAudit func(int, string, string, interface{}, map[string]interface{}, *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request data"})
			return
		}

		// Find user
		var user models.User
		err := db.QueryRow(`
			SELECT id, username, email, first_name, last_name, password_hash, is_active
			FROM users WHERE username = $1
		`, req.Username).Scan(&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName, &user.PasswordHash, &user.IsActive)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid credentials"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Database error"})
			return
		}

		if !user.IsActive {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Account is deactivated"})
			return
		}

		// Check password
		if !checkPasswordHash(req.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid credentials"})
			return
		}

		// Get user roles
		roles, err := database.GetUserRoles(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to get user roles"})
			return
		}

		// Generate tokens
		accessToken, err := generateAccessToken(user.ID, user.Username, roles)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to generate access token"})
			return
		}

		refreshToken, err := generateRefreshToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to generate refresh token"})
			return
		}

		// Store refresh token
		err = database.StoreRefreshToken(user.ID, refreshToken, time.Now().Add(7*24*time.Hour))
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to store refresh token"})
			return
		}

		// Update last login
		_, err = db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", user.ID)
		if err != nil {
			fmt.Printf("Failed to update last login: %v\n", err)
		}

		// Log audit
		logAudit(user.ID, "login", "auth", nil, map[string]interface{}{
			"username": user.Username,
		}, c)

		userInfo := models.UserInfo{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Roles:     roles,
		}

		c.JSON(http.StatusOK, models.LoginResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			User:         userInfo,
		})
	}
}

// RefreshTokenHandler handles token refresh
// @Summary Refresh access token
// @Description Use refresh token to get new access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RefreshRequest true "Refresh token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/refresh [post]
func RefreshTokenHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request data"})
			return
		}

		// Validate refresh token
		userID, valid := database.IsRefreshTokenValid(req.RefreshToken)
		if !valid {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid or expired refresh token"})
			return
		}

		// Get user info
		var username string
		err := db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to get user info"})
			return
		}

		// Get user roles
		roles, err := database.GetUserRoles(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to get user roles"})
			return
		}

		// Generate new access token
		accessToken, err := generateAccessToken(userID, username, roles)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to generate access token"})
			return
		}

		// Optionally generate new refresh token
		newRefreshToken, err := generateRefreshToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to generate refresh token"})
			return
		}

		// Store new refresh token and revoke old one
		err = database.StoreRefreshToken(userID, newRefreshToken, time.Now().Add(7*24*time.Hour))
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to store refresh token"})
			return
		}

		err = database.RevokeRefreshToken(req.RefreshToken)
		if err != nil {
			fmt.Printf("Failed to revoke old refresh token: %v\n", err)
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
		})
	}
}

// Logout handles user logout
// @Summary Logout user
// @Description Revoke refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RefreshRequest true "Refresh token to revoke"
// @Success 200 {object} map[string]string
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /auth/logout [post]
func Logout(db *sql.DB, logAudit func(int, string, string, interface{}, map[string]interface{}, *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request data"})
			return
		}

		// Revoke refresh token
		err := database.RevokeRefreshToken(req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to revoke token"})
			return
		}

		// Log audit (userID might not be available, so use 0 or try to extract from token)
		logAudit(0, "logout", "auth", nil, map[string]interface{}{
			"token_revoked": true,
		}, c)

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}