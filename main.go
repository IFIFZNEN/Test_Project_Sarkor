package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// JWT secret key
var jwtKey = []byte("123")

// JWT claims struct
type Claims struct {
	UserID string `json:"user_id"`
	Login  string `json:"login"`
	jwt.StandardClaims
}

func main() {
	var err error
	// Initialize the database
	db, err = sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create users table if not exists
	createUsersTable := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		login TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		name TEXT NOT NULL,
		age INTEGER NOT NULL
	);`
	_, err = db.Exec(createUsersTable)
	if err != nil {
		panic(err)
	}

	// Create phones table if not exists
	createPhonesTable := `CREATE TABLE IF NOT EXISTS phones (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		phone TEXT NOT NULL,
		description TEXT,
		is_fax BOOLEAN NOT NULL DEFAULT 0,
		UNIQUE(user_id, phone)
	);`
	_, err = db.Exec(createPhonesTable)
	if err != nil {
		panic(err)
	}

	r := gin.Default()

	r.POST("/user/register", registerHandler)
	r.POST("/user/auth", authHandler)
	r.GET("/user/:name", authMiddleware(), getUserHandler)
	r.POST("/user/phone", authMiddleware(), addPhoneHandler)
	r.GET("/user/phone", authMiddleware(), getPhoneHandler)
	r.PUT("/user/phone", authMiddleware(), updatePhoneHandler)
	r.DELETE("/user/phone/:phone_id", authMiddleware(), deletePhoneHandler)

	r.Run(":8080")
}

// Define other handlers and middleware here...

func registerHandler(c *gin.Context) {
	// Parse form data
	login := c.PostForm("login")
	password := c.PostForm("password")
	name := c.PostForm("name")
	age := c.PostForm("age")

	// Validate input
	if login == "" || password == "" || name == "" || age == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "All fields are required"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Insert the user into the database
	stmt, err := db.Prepare("INSERT INTO users(login, password, name, age) VALUES(?, ?, ?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(login, string(hashedPassword), name, age)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
		return
	}

	// Respond with success
	c.JSON(http.StatusCreated, gin.H{"status": "Account created successfully"})
}

func authHandler(c *gin.Context) {
	// Структура для парсинга входных данных
	var credentials struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	// Парсим входные данные
	if err := c.BindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Ищем пользователя в базе данных
	stmt, err := db.Prepare("SELECT id, password FROM users WHERE login = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer stmt.Close()

	var hashedPassword string
	var userID int
	err = stmt.QueryRow(credentials.Login).Scan(&userID, &hashedPassword)
	if err != nil {
		// Если пользователя не существует или другая ошибка запроса
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid login credentials"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Сверяем пароли
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
	if err != nil {
		// Пароль не совпадает
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid login credentials"})
		return
	}

	// Пароль совпадает, генерируем JWT
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID: strconv.Itoa(userID), // Преобразуем userID в строку
		Login:  credentials.Login,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating the JWT token"})
		return
	}

	// Устанавливаем куки
	c.SetCookie("SESSTOKEN", tokenString, int(expirationTime.Sub(time.Now()).Seconds()), "/", "", false, true)

	// Отправляем успешный ответ
	c.JSON(http.StatusOK, gin.H{"status": "Logged in successfully"})
}

func getUserHandler(c *gin.Context) {
	// Извлекаем имя из параметра пути
	name := c.Param("name")

	// Подготавливаем запрос к базе данных для поиска пользователя по имени
	stmt, err := db.Prepare("SELECT id, name, age FROM users WHERE name = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer stmt.Close()

	// Выполняем запрос
	var id int
	var retrievedName string
	var age int
	err = stmt.QueryRow(name).Scan(&id, &retrievedName, &age)
	if err != nil {
		// Если пользователя не найдено
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Если пользователь найден, возвращаем его данные
	c.JSON(http.StatusOK, gin.H{"id": id, "name": retrievedName, "age": age})
}

func addPhoneHandler(c *gin.Context) {
	// Структура для входящих данных
	var phoneData struct {
		Phone       string `json:"phone"`
		Description string `json:"description"`
		IsFax       bool   `json:"is_fax"`
	}

	// Парсим входящий JSON
	if err := c.BindJSON(&phoneData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
	userID, err := getUserIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Проверяем, существует ли уже такой номер телефона для этого пользователя
	var existingPhoneID int
	err = db.QueryRow("SELECT id FROM phones WHERE user_id = ? AND phone = ?", userID, phoneData.Phone).Scan(&existingPhoneID)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number already exists"})
		return
	}

	// Вставляем новый номер телефона в базу данных
	stmt, err := db.Prepare("INSERT INTO phones (user_id, phone, description, is_fax) VALUES (?, ?, ?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID, phoneData.Phone, phoneData.Description, phoneData.IsFax)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
		return
	}

	// Отправляем подтверждение об успешном добавлении
	c.JSON(http.StatusCreated, gin.H{"status": "Phone number added successfully"})
}

func getPhoneHandler(c *gin.Context) {
	// Получаем поисковый запрос из параметров запроса
	searchQuery := c.Query("q")

	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
	userID, err := getUserIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Подготавливаем SQL-запрос для поиска номеров телефонов, соответствующих поисковому запросу
	rows, err := db.Query("SELECT id, phone, description, is_fax FROM phones WHERE user_id = ? AND phone LIKE ?", userID, "%"+searchQuery+"%")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	// Создаем слайс для хранения результатов
	phones := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int
		var phone, description string
		var isFax bool

		// Считываем данные
		if err := rows.Scan(&id, &phone, &description, &isFax); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// Добавляем полученные данные в слайс
		phones = append(phones, map[string]interface{}{
			"id":          id,
			"phone":       phone,
			"description": description,
			"is_fax":      isFax,
		})
	}

	// Проверяем, есть ли ошибка при итерации по результатам запроса
	if err = rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Отправляем результат
	c.JSON(http.StatusOK, phones)
}

func updatePhoneHandler(c *gin.Context) {
	// Структура для входящих данных
	var updateData struct {
		PhoneID     int    `json:"phone_id"`
		Phone       string `json:"phone"`
		Description string `json:"description"`
		IsFax       bool   `json:"is_fax"`
	}

	// Парсим входящий JSON
	if err := c.BindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
	userID, err := getUserIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Обновляем данные номера телефона в базе данных
	stmt, err := db.Prepare("UPDATE phones SET phone = ?, description = ?, is_fax = ? WHERE id = ? AND user_id = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(updateData.Phone, updateData.Description, updateData.IsFax, updateData.PhoneID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
		return
	}

	// Проверяем, была ли обновлена какая-либо запись
	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No phone record found to update"})
		return
	}

	// Отправляем подтверждение об успешном обновлении
	c.JSON(http.StatusOK, gin.H{"status": "Phone number updated successfully"})
}

// getUserIDFromToken извлекает и возвращает user_id из токена пользователя
func getUserIDFromToken(c *gin.Context) (int, error) {
	// Предполагается, что вы уже реализовали извлечение и проверку JWT токена,
	// которая возвращает ID пользователя
	// Например, вы могли бы декодировать токен из куки и вернуть user_id
	return 0, nil // Замените этот код на вашу реализацию
}

func deletePhoneHandler(c *gin.Context) {
	// Извлекаем phone_id из параметра пути
	phoneID := c.Param("phone_id")

	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
	userID, err := getUserIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Подготавливаем SQL-запрос для удаления номера телефона
	stmt, err := db.Prepare("DELETE FROM phones WHERE id = ? AND user_id = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
		return
	}
	defer stmt.Close()

	// Выполняем запрос
	result, err := stmt.Exec(phoneID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
		return
	}

	// Проверяем, была ли удалена какая-либо запись
	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No phone record found to delete"})
		return
	}

	// Отправляем подтверждение об успешном удалении
	c.JSON(http.StatusOK, gin.H{"status": "Phone number deleted successfully"})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Извлекаем куки SESSTOKEN из запроса
		tokenString, err := c.Cookie("SESSTOKEN")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "You need to be logged in to access this resource"})
			c.Abort()
			return
		}

		// Парсим токен
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			// Проверяем, что алгоритм подписи тот, что мы ожидаем
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
			c.Abort()
			return
		}

		// Валидируем токен и извлекаем claims
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			// Добавляем информацию из claims в контекст запроса
			c.Set("userID", claims.UserID)
			c.Set("login", claims.Login)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
