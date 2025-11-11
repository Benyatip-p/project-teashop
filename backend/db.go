package main

import (
    "database/sql"
    "fmt"
    "log"
    "os"

    _ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
    host := os.Getenv("DB_HOST")
    port := os.Getenv("DB_PORT")
    user := os.Getenv("DB_USER")
    password := os.Getenv("DB_PASSWORD")
    name := os.Getenv("DB_NAME")

    if host == "" || port == "" || user == "" || password == "" || name == "" {
        log.Fatal("DB environment variables are not set properly")
    }

    connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
        host, port, user, password, name)

    var err error
    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatalf("Failed to connect DB: %v", err)
    }

    if err = db.Ping(); err != nil {
        log.Fatalf("Cannot ping DB: %v", err)
    }

    log.Println("✅ Connected to DB")
}

func GetDB() *sql.DB {
    return db
}
