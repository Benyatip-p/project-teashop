package main

import (
	_ "backend/docs"
	"backend/auth"
	"backend/database"
	"backend/handlers"
	"backend/middleware"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/files"
)

// @title Tea Shop API
// @version 1.0
// @description A tea shop API with user authentication and product management
// @host localhost:8080
// @schemes http
// @BasePath

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	database.InitDB()
	defer database.DB.Close()

	r := gin.Default()
	r.Use(cors.Default())

	// ===================== Public Endpoints =====================
	// Health check
	r.GET("/health", func(c *gin.Context){
		err := database.DB.Ping()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"message":"unhealthy", "error":err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message" : "healthy"})
	})

	// Swagger endpoint
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ===================== Authentication Endpoints =====================
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", auth.Register(database.DB, database.LogAudit))
		authGroup.POST("/login", auth.Login(database.DB, database.LogAudit))
		authGroup.POST("/refresh", auth.RefreshTokenHandler(database.DB))
		authGroup.POST("/logout", auth.Logout(database.DB, database.LogAudit))
	}

	// ===================== Public API Endpoints =====================
	api := r.Group("/api/v1")
	{
		// Public endpoints
		api.GET("/products", handlers.GetProductsHandler)
		api.GET("/products/:id/reviews", handlers.GetProductReviewsHandler)
		api.GET("/products/:id", handlers.GetProductByIDHandler)
		api.GET("/categories", handlers.GetCategoriesHandler)
		api.GET("/categories/:id/products", handlers.GetProductsByCategoryHandler)
		api.GET("/products/top-selling", handlers.GetTopSellingProductsHandler)
		api.GET("/variants/product/:product_id", handlers.GetVariantsByProductHandler)
		api.GET("/categories/featured", handlers.GetFeaturedCategoriesHandler)
		api.GET("/products/featured", handlers.GetFeaturedProductsHandler)

		// Protected endpoints
		protected := api.Group("/")
		protected.Use(middleware.AuthMiddleware())
		{
			protected.GET("/profile", handlers.GetMyProfileHandler)
			protected.PUT("/profile", handlers.UpdateProfileHandler)
			protected.GET("/addresses", handlers.GetAddressesHandler)
			protected.GET("/addresses/default", handlers.GetDefaultAddressHandler)
			protected.POST("/addresses", handlers.CreateAddressHandler)
			protected.PUT("/addresses/:id", handlers.UpdateAddressHandler)
			protected.DELETE("/addresses/:id", handlers.DeleteAddressHandler)
			protected.POST("/products/:id/reviews", handlers.CreateReviewHandler)
			protected.POST("/orders", handlers.CreateOrderHandler)
			protected.GET("/orders", handlers.GetUserOrdersHandler)
			protected.GET("/orders/:id", handlers.GetOrderDetailsHandler)
			protected.GET("/orders/status", handlers.GetOrdersByStatusHandler)
			protected.GET("/admin/spending", handlers.GetAllUsersSpendingHandler) // (admin only)
			protected.GET("/admin/sales/daily", handlers.GetDailySalesHandler) // (admin only)
			protected.GET("/admin/sales/monthly", handlers.GetMonthlySalesHandler) // (admin only)
			protected.GET("/admin/sales/yearly", handlers.GetYearlySalesHandler) // (admin only)
			protected.GET("/admin/sales/history/monthly", handlers.GetMonthlySalesHistoryHandler) // (admin only)
			protected.GET("/admin/sales/history/yearly", handlers.GetYearlySalesHistoryHandler) // (admin only)
			protected.GET("/admin/items/low-stock", handlers.GetLowStockItemsHandler) // (admin only)
			protected.GET("/admin/variants/low-stock", handlers.GetLowStockVariantsHandler) // (admin only)
			protected.GET("/admin/users/stats", handlers.GetUserStatsHandler) // (admin only)
			protected.PUT("/orders/:id/status", handlers.UpdateOrderStatusHandler) 
			protected.POST("/orders/:id/cancel", handlers.CancelOrderHandler)
			protected.DELETE("/products/:id", handlers.DeleteProductHandler) // delete (admin only)
			protected.POST("/products", handlers.CreateProductHandler)    // add (admin only)
			protected.PUT("/products/:id", handlers.UpdateProductHandler) // edit (admin only)
			protected.POST("/variants/product/:product_id", handlers.CreateVariantHandler) // admin only
			protected.PUT("/variants/:id", handlers.UpdateVariantHandler) // admin only
			protected.DELETE("/variants/:id", handlers.DeleteVariantHandler) // admin only
		}
	}

	r.Run(":8080")
}