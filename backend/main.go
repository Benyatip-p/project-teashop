package main

import (
	"backend/config"
	"backend/routes"
	"log"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.InitDB()
	defer config.DB.Close()

	r := gin.Default()
	r.Use(cors.Default())

	// Health check
	r.GET("/health", func(c *gin.Context) {
		if err := config.DB.Ping(); err != nil {
			c.JSON(503, gin.H{"message": "unhealthy", "error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "healthy"})
	})

	// Routes
	routes.RegisterAuthRoutes(r)
	routes.RegisterProductRoutes(r)

	log.Println("Server running on :8081")
	r.Run(":8081")
}
