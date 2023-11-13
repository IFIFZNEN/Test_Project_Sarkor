package main

// import (
// 	"database/sql"
// 	"fmt"
// 	"net/http"
// 	"strconv"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gin-gonic/gin"
// 	_ "github.com/mattn/go-sqlite3"
// 	"golang.org/x/crypto/bcrypt"
// )

// var db *sql.DB

// // JWT secret key
// var jwtKey = []byte("123")

// // JWT claims struct
// type Claims struct {
// 	UserID string `json:"user_id"`
// 	Login  string `json:"login"`
// 	jwt.StandardClaims
// }

// func main() {
// 	var err error
// 	// Initialize the database
// 	db, err = sql.Open("sqlite3", "./test.db")
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer db.Close()

// 	// Create users table if not exists
// 	createUsersTable := `CREATE TABLE IF NOT EXISTS users (
// 		id INTEGER PRIMARY KEY AUTOINCREMENT,
// 		login TEXT NOT NULL UNIQUE,
// 		password TEXT NOT NULL,
// 		name TEXT NOT NULL,
// 		age INTEGER NOT NULL
// 	);`
// 	_, err = db.Exec(createUsersTable)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Create phones table if not exists
// 	createPhonesTable := `CREATE TABLE IF NOT EXISTS phones (
// 		id INTEGER PRIMARY KEY AUTOINCREMENT,
// 		user_id INTEGER NOT NULL,
// 		phone TEXT NOT NULL,
// 		description TEXT,
// 		is_fax BOOLEAN NOT NULL DEFAULT 0,
// 		UNIQUE(user_id, phone)
// 	);`
// 	_, err = db.Exec(createPhonesTable)
// 	if err != nil {
// 		panic(err)
// 	}

// 	r := gin.Default()

// 	r.POST("/user/register", registerHandler)
// 	r.POST("/user/auth", authHandler)
// 	r.GET("/user/:name", authMiddleware(), getUserHandler)
// 	r.POST("/user/phone", authMiddleware(), addPhoneHandler)
// 	r.GET("/user/phone", authMiddleware(), getPhoneHandler)
// 	r.PUT("/user/phone", authMiddleware(), updatePhoneHandler)
// 	r.DELETE("/user/phone/:phone_id", authMiddleware(), deletePhoneHandler)

// 	r.Run(":8080")
// }

// // Define other handlers and middleware here...

// func registerHandler(c *gin.Context) {
// 	// Parse form data
// 	login := c.PostForm("login")
// 	password := c.PostForm("password")
// 	name := c.PostForm("name")
// 	age := c.PostForm("age")

// 	// Validate input
// 	if login == "" || password == "" || name == "" || age == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "All fields are required"})
// 		return
// 	}

// 	// Hash password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
// 		return
// 	}

// 	// Insert the user into the database
// 	stmt, err := db.Prepare("INSERT INTO users(login, password, name, age) VALUES(?, ?, ?, ?)")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
// 		return
// 	}
// 	defer stmt.Close()

// 	_, err = stmt.Exec(login, string(hashedPassword), name, age)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
// 		return
// 	}

// 	// Respond with success
// 	c.JSON(http.StatusCreated, gin.H{"status": "Account created successfully"})
// }

// func authHandler(c *gin.Context) {
// 	// Структура для парсинга входных данных
// 	var credentials struct {
// 		Login    string `json:"login"`
// 		Password string `json:"password"`
// 	}

// 	// Парсим входные данные
// 	if err := c.BindJSON(&credentials); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
// 		return
// 	}

// 	// Ищем пользователя в базе данных
// 	stmt, err := db.Prepare("SELECT id, password FROM users WHERE login = ?")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		return
// 	}
// 	defer stmt.Close()

// 	var hashedPassword string
// 	var userID int
// 	err = stmt.QueryRow(credentials.Login).Scan(&userID, &hashedPassword)
// 	if err != nil {
// 		// Если пользователя не существует или другая ошибка запроса
// 		if err == sql.ErrNoRows {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid login credentials"})
// 		} else {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		}
// 		return
// 	}

// 	// Сверяем пароли
// 	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
// 	if err != nil {
// 		// Пароль не совпадает
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid login credentials"})
// 		return
// 	}

// 	// Пароль совпадает, генерируем JWT
// 	expirationTime := time.Now().Add(1 * time.Hour)
// 	claims := &Claims{
// 		UserID: strconv.Itoa(userID), // Преобразуем userID в строку
// 		Login:  credentials.Login,
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: expirationTime.Unix(),
// 		},
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating the JWT token"})
// 		return
// 	}

// 	// Устанавливаем куки
// 	c.SetCookie("SESSTOKEN", tokenString, int(expirationTime.Sub(time.Now()).Seconds()), "/", "", false, true)

// 	// Отправляем успешный ответ
// 	c.JSON(http.StatusOK, gin.H{"status": "Logged in successfully"})
// }

// func getUserHandler(c *gin.Context) {
// 	// Извлекаем имя из параметра пути
// 	name := c.Param("name")

// 	// Подготавливаем запрос к базе данных для поиска пользователя по имени
// 	stmt, err := db.Prepare("SELECT id, name, age FROM users WHERE name = ?")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		return
// 	}
// 	defer stmt.Close()

// 	// Выполняем запрос
// 	var id int
// 	var retrievedName string
// 	var age int
// 	err = stmt.QueryRow(name).Scan(&id, &retrievedName, &age)
// 	if err != nil {
// 		// Если пользователя не найдено
// 		if err == sql.ErrNoRows {
// 			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
// 		} else {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		}
// 		return
// 	}

// 	// Если пользователь найден, возвращаем его данные
// 	c.JSON(http.StatusOK, gin.H{"id": id, "name": retrievedName, "age": age})
// }

// func addPhoneHandler(c *gin.Context) {
// 	// Структура для входящих данных
// 	var phoneData struct {
// 		Phone       string `json:"phone"`
// 		Description string `json:"description"`
// 		IsFax       bool   `json:"is_fax"`
// 	}

// 	// Парсим входящий JSON
// 	if err := c.BindJSON(&phoneData); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
// 		return
// 	}

// 	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
// 	userID, err := getUserIDFromToken(c)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	// Проверяем, существует ли уже такой номер телефона для этого пользователя
// 	var existingPhoneID int
// 	err = db.QueryRow("SELECT id FROM phones WHERE user_id = ? AND phone = ?", userID, phoneData.Phone).Scan(&existingPhoneID)
// 	if err != sql.ErrNoRows {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number already exists"})
// 		return
// 	}

// 	// Вставляем новый номер телефона в базу данных
// 	stmt, err := db.Prepare("INSERT INTO phones (user_id, phone, description, is_fax) VALUES (?, ?, ?, ?)")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
// 		return
// 	}
// 	defer stmt.Close()

// 	_, err = stmt.Exec(userID, phoneData.Phone, phoneData.Description, phoneData.IsFax)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
// 		return
// 	}

// 	// Отправляем подтверждение об успешном добавлении
// 	c.JSON(http.StatusCreated, gin.H{"status": "Phone number added successfully"})
// }

// func getPhoneHandler(c *gin.Context) {
// 	// Получаем поисковый запрос из параметров запроса
// 	searchQuery := c.Query("q")

// 	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
// 	userID, err := getUserIDFromToken(c)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	// Подготавливаем SQL-запрос для поиска номеров телефонов, соответствующих поисковому запросу
// 	rows, err := db.Query("SELECT id, phone, description, is_fax FROM phones WHERE user_id = ? AND phone LIKE ?", userID, "%"+searchQuery+"%")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		return
// 	}
// 	defer rows.Close()

// 	// Создаем слайс для хранения результатов
// 	phones := make([]map[string]interface{}, 0)
// 	for rows.Next() {
// 		var id int
// 		var phone, description string
// 		var isFax bool

// 		// Считываем данные
// 		if err := rows.Scan(&id, &phone, &description, &isFax); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 			return
// 		}

// 		// Добавляем полученные данные в слайс
// 		phones = append(phones, map[string]interface{}{
// 			"id":          id,
// 			"phone":       phone,
// 			"description": description,
// 			"is_fax":      isFax,
// 		})
// 	}

// 	// Проверяем, есть ли ошибка при итерации по результатам запроса
// 	if err = rows.Err(); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
// 		return
// 	}

// 	// Отправляем результат
// 	c.JSON(http.StatusOK, phones)
// }

// func updatePhoneHandler(c *gin.Context) {
// 	// Структура для входящих данных
// 	var updateData struct {
// 		PhoneID     int    `json:"phone_id"`
// 		Phone       string `json:"phone"`
// 		Description string `json:"description"`
// 		IsFax       bool   `json:"is_fax"`
// 	}

// 	// Парсим входящий JSON
// 	if err := c.BindJSON(&updateData); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
// 		return
// 	}

// 	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
// 	userID, err := getUserIDFromToken(c)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	// Обновляем данные номера телефона в базе данных
// 	stmt, err := db.Prepare("UPDATE phones SET phone = ?, description = ?, is_fax = ? WHERE id = ? AND user_id = ?")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
// 		return
// 	}
// 	defer stmt.Close()

// 	result, err := stmt.Exec(updateData.Phone, updateData.Description, updateData.IsFax, updateData.PhoneID, userID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
// 		return
// 	}

// 	// Проверяем, была ли обновлена какая-либо запись
// 	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "No phone record found to update"})
// 		return
// 	}

// 	// Отправляем подтверждение об успешном обновлении
// 	c.JSON(http.StatusOK, gin.H{"status": "Phone number updated successfully"})
// }

// // getUserIDFromToken извлекает и возвращает user_id из токена пользователя
// func getUserIDFromToken(c *gin.Context) (int, error) {
// 	// Предполагается, что вы уже реализовали извлечение и проверку JWT токена,
// 	// которая возвращает ID пользователя
// 	// Например, вы могли бы декодировать токен из куки и вернуть user_id
// 	return 0, nil // Замените этот код на вашу реализацию
// }

// func deletePhoneHandler(c *gin.Context) {
// 	// Извлекаем phone_id из параметра пути
// 	phoneID := c.Param("phone_id")

// 	// Извлекаем user_id из JWT, предполагается, что функция `getUserIDFromToken` уже реализована
// 	userID, err := getUserIDFromToken(c)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	// Подготавливаем SQL-запрос для удаления номера телефона
// 	stmt, err := db.Prepare("DELETE FROM phones WHERE id = ? AND user_id = ?")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare database statement"})
// 		return
// 	}
// 	defer stmt.Close()

// 	// Выполняем запрос
// 	result, err := stmt.Exec(phoneID, userID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute database statement"})
// 		return
// 	}

// 	// Проверяем, была ли удалена какая-либо запись
// 	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "No phone record found to delete"})
// 		return
// 	}

// 	// Отправляем подтверждение об успешном удалении
// 	c.JSON(http.StatusOK, gin.H{"status": "Phone number deleted successfully"})
// }

// func authMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Извлекаем куки SESSTOKEN из запроса
// 		tokenString, err := c.Cookie("SESSTOKEN")
// 		if err != nil {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "You need to be logged in to access this resource"})
// 			c.Abort()
// 			return
// 		}

// 		// Парсим токен
// 		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
// 			// Проверяем, что алгоритм подписи тот, что мы ожидаем
// 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 			}
// 			return jwtKey, nil
// 		})

// 		if err != nil {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
// 			c.Abort()
// 			return
// 		}

// 		// Валидируем токен и извлекаем claims
// 		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
// 			// Добавляем информацию из claims в контекст запроса
// 			c.Set("userID", claims.UserID)
// 			c.Set("login", claims.Login)
// 		} else {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
// 			c.Abort()
// 			return
// 		}

// 		c.Next()
// 	}
// }

// Implement the handlers and middleware...

/*



























import (
	"database/sql"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func readSecretKeyfromFile(file string) string {
	str, err := os.ReadFile("secret_key.txt")
	if err != nil {
		panic(err)
	}
	return string(str)
}

var jwtKey = readSecretKeyfromFile // Секретный ключ

type Credentials struct {
	Password string `json:"password"`
	Login    string `json:"login"`
}

type Claims struct {
	Login string `json:"login"`
	jwt.StandardClaims
}

type PhoneInfo struct {
	Phone       string `json:"phone"`
	Description string `json:"description"`
	IsFax       bool   `json:"is_fax"`
}

func main() {

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := gin.Default()

	// РЕГИСТРАЦИЯ!
	r.POST("/user/register", func(c *gin.Context) {
		login := c.PostForm("login")
		password := c.PostForm("password")
		name := c.PostForm("name")
		ageStr := c.PostForm("age")

		// Convert age from string to int
		age, err := strconv.Atoi(ageStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Недопустимое значение возраста!"})
			return
		}

		// Hashing the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось хешировать пароль!"})
			return
		}

		// Preparing SQL statement
		stmt, err := db.Prepare("INSERT INTO users(login, password, name, age) VALUES(?, ?, ?, ?)")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось подготовить SQL запрос!"})
			return
		}
		defer stmt.Close()

		// Executing SQL statement
		_, err = stmt.Exec(login, hashedPassword, name, age)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось выполнить SQL запрос!"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Регистрация пользователя успешно завершена!"}) // для проверки требуется запустить консоль в записать следующую команду: "curl -d "login=user&password=pass&name=John&age=30" -X POST http://localhost:8080/user/register"

	})

	// АВТОРИЗАЦИЯ!
	r.POST("/user/auth", func(c *gin.Context) { // для проверки авторизации использовуем команду: "curl -v -H "Content-Type: application/json" -d "{\"login\":\"пиши логин\",\"password\":\"пиши пароль\"}" -X POST http://localhost:8080/user/auth"

		var creds Credentials
		// Получаем данные из JSON
		if err := c.ShouldBindJSON(&creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Неправильный запрос!"})
			return
		}

		// Ищем пользователя в базе данных
		var hashedPassword string
		var id int
		err := db.QueryRow("SELECT id, password FROM users WHERE login = ?", creds.Login).Scan(&id, &hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				// Если пользователь не найден, возвращаем ошибку
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверные логин или пароль!"})
				return
			}
			// Если возникла другая ошибка при запросе к БД, возвращаем ошибку сервера
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка сервера!"})
			return
		}

		// Сравниваем предоставленный пароль с сохраненным хешем
		if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password)); err != nil {
			// Если пароли не совпадают, возвращаем ошибку
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверные логин или пароль!"})
			return
		}

		// Создаем новый токен для пользователя
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Login: creds.Login,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
				Id:        strconv.Itoa(id),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не получается создать токен!"})
			return
		}

		// Устанавливаем токен в куки
		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "SESSTOKEN",
			Value:   tokenString,
			Expires: expirationTime,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Успешный вход!"})
	})

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "ПРИВЕТ, МИР!",
		})
	})

	r.GET("/user/:name", AuthMiddleware(), func(c *gin.Context) { // Отображает информацию ввиде JSON curl -X GET -b "SESSTOKEN=ТУТ ТОКЕН" http://localhost:8080/user/ТУТ ИМЯ ПОЛЬЗОВАТЕЛЯ
		name := c.Param("name") // SESSTOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6ImlmaWZ6bmVuIiwiZXhwIjoxNjk5NjExNDMzLCJqdGkiOiJcdTAwMDIifQ.Ep_eQXo8RuB2uurLXWSam9IQ7Gt9vDSaKI--ZoBbd14

		// Поиск пользователя в БД
		var user struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Age  int    `json:"age"`
		}

		err := db.QueryRow("SELECT id, name, age FROM users WHERE name = ?", name).Scan(&user.ID, &user.Name, &user.Age)
		if err != nil {
			if err == sql.ErrNoRows {
				// Если пользователь не найден, возвращаем ошибку
				c.JSON(http.StatusNotFound, gin.H{"message": "Пользователь не найден"})
				return
			}
			// Если возникла другая ошибка при запросе к БД, возвращаем ошибку сервера
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка сервера"})
			return
		}

		c.JSON(http.StatusOK, user)
	})

	r.POST("/user/phone", AuthMiddleware(), func(c *gin.Context) {
		var phoneInfo PhoneInfo
		if err := c.ShouldBindJSON(&phoneInfo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный запрос"})
			return
		}

		// Извлекаем информацию о пользователе из токена
		userInfo, _ := c.Get("userInfo")
		claims, _ := userInfo.(*Claims)

		// Проверяем, существует ли уже такой номер в базе данных
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM phones WHERE phone = ?", phoneInfo.Phone).Scan(&exists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка проверки существования телефона"})
			return
		}
		if exists > 0 {
			c.JSON(http.StatusConflict, gin.H{"message": "Номер телефона уже существует"})
			return
		}

		// Добавляем информацию о телефоне в базу данных
		stmt, err := db.Prepare("INSERT INTO phones (user_id, phone, description, is_fax) VALUES (?, ?, ?, ?)")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось подготовить SQL запрос"})
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(claims.Id, phoneInfo.Phone, phoneInfo.Description, phoneInfo.IsFax)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось выполнить SQL запрос"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Номер телефона успешно добавлен"})
	})

	r.Run() // дефолтный порт :8080

}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получаем куки SESSTOKEN
		tokenString, err := c.Cookie("SESSTOKEN")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Токен не найден!"})
			c.Abort()
			return
		}

		// Парсим токен
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Неправильный токен"})
			c.Abort()
			return
		}

		// Добавляем информацию о пользователе в контекст
		c.Set("userInfo", claims)
		c.Next()
	}
}

*/
