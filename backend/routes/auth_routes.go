package routes

import (
	"backend/controllers"
	
	 "backend/middlewares"
	"github.com/gin-gonic/gin"
)


func RegisterAuthRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/login", controllers.Login)
		// ใส่ middleware ตรวจสอบ JWT
		auth.GET("/profile", middlewares.AuthMiddleware(), controllers.GetProfile)
	}
}