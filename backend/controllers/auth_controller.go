package controllers

import (
	"backend/config"
	"backend/models"
	"backend/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var user models.User
	err := config.DB.QueryRow(`
		SELECT id, username, email, first_name, last_name, password_hash, is_active
		FROM users WHERE username=$1
	`, req.Username).Scan(&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName, &user.PasswordHash, &user.IsActive)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account disabled"})
		return
	}

	// เปรียบเทียบรหัสผ่าน
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// ดึง roles จริงจาก DB
	var roles []string
	rows, err := config.DB.Query(`
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id=$1
	`, user.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var role string
			rows.Scan(&role)
			roles = append(roles, role)
		}
	}

	// สร้าง access token
	accessToken, _ := utils.GenerateAccessToken(user.ID, user.Username, roles)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"roles":    roles,
		},
	})
}

func GetProfile(c *gin.Context) {
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDInterface.(int)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id type"})
		return
	}

	var user models.User
	err := config.DB.QueryRow(`
		SELECT id, username, email, first_name, last_name, is_active
		FROM users WHERE id=$1
	`, userID).Scan(&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName, &user.IsActive)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":        user.ID,
		"username":  user.Username,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
	})
}
