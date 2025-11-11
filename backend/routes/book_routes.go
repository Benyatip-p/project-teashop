package routes

import (
	"backend/controllers"
	"backend/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterProductRoutes(r *gin.Engine) {
	// ใช้ middleware ตรวจสอบ JWT
	product := r.Group("/products")
	product.Use(middlewares.AuthMiddleware())
	{
		product.GET("/", controllers.GetProducts)                 // ดูสินค้าทั้งหมด
		product.GET("/:id", controllers.GetProductByID)          // ดูสินค้าชิ้นเดียวตาม ID
		product.GET("/category", controllers.GetCategories)      // ดูหมวดหมู่ทั้งหมด
		product.GET("/category/:id", controllers.GetProductsByCategory) // ดูสินค้าในหมวดหมู่
	}
}
