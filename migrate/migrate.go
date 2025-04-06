package main

import (
	"fmt"
	"log"

	"github.com/sagar-rathod-devops/golang-gorm-postgres/initializers"
	"github.com/sagar-rathod-devops/golang-gorm-postgres/models"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("❌ Could not load environment variables:", err)
	}

	initializers.ConnectDB(&config)
}

func main() {
	// ✅ Enable uuid-ossp extension
	if err := initializers.DB.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		log.Fatal("❌ Failed to create uuid-ossp extension:", err)
	}

	// ✅ Auto-migrate User model
	if err := initializers.DB.AutoMigrate(&models.User{}, &models.Post{}); err != nil {
		log.Fatal("❌ Migration failed:", err)
	}

	fmt.Println("✅ Migration complete")
}
