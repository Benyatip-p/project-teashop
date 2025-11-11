package middlewares

import (
	"backend/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware ตรวจสอบ JWT token
// AuthMiddleware ตรวจสอบ JWT token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		claims, err := utils.VerifyToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// เพราะ claims.UserID เป็น int อยู่แล้ว
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

// RequirePermission ตรวจสอบ permission ของผู้ใช้
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDInterface, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		userID, ok := userIDInterface.(int)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id type"})
			c.Abort()
			return
		}

		if !utils.CheckUserPermission(userID, permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "insufficient permissions",
				"required": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
