package main

import (
	"C"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", "mydb.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создайте таблицу, если она не существует
	createTable()

	// Создайте экземпляр Gin
	r := gin.Default()

	// Обработчик для вывода "Hello, World!" на главной странице
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, World!")
	})

	// Обработчик для получения данных из базы данных
	r.GET("/data", getData)

	// Запустите веб-сервер на порту 8080
	r.Run(":8080")
}

func createTable() {
	createTableSQL := `
        CREATE TABLE IF NOT EXISTS data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT
        );
    `
	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}
}

func getData(c *gin.Context) {
	rows, err := db.Query("SELECT id, name FROM data")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var data string
	for rows.Next() {
		err := rows.Scan(&data)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(data)
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}
