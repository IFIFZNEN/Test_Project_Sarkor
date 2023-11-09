/*
	ПУНКТ 1. ЗАПУСК И СОЗДАНИЕ СЕРВЕРА. ВЫВОД НА ЭКРАН "HELLO WORLD" по ссылке http://localhost:8080/
*/

package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Созданиче SQL таблицы
	sql_table := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login VARCHAR NOT NULL,
        password VARCHAR NOT NULL,
        name VARCHAR NOT NULL,
        age INTEGER
    );`

	_, err = db.Exec(sql_table)
	if err != nil {
		panic(err)
	}

	// Запуск Джин
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "hello world",
		})
	})

	// Запуск тут
	r.Run() // Дефолтные значения :8080
}
