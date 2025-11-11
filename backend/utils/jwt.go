package utils

import (
	"backend/config"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var JwtSecret = []byte("my-super-secret-key-change-in-production")

type CustomClaims struct {
	UserID   int      `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID int, username string, roles []string) (string, error) {
	exp := time.Now().Add(15 * time.Minute)
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "backend-api",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret)
}

func VerifyToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ตัวอย่าง CheckUserPermission
func CheckUserPermission(userID int, permission string) bool {
	var count int
	err := config.DB.QueryRow(`
		SELECT COUNT(*)
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id=$1 AND p.name=$2
	`, userID, permission).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
