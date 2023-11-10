package main

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
				Id:        string(id),
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
		name := c.Param("name")

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
				c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
				return
			}
			// Если возникла другая ошибка при запросе к БД, возвращаем ошибку сервера
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
			return
		}

		c.JSON(http.StatusOK, user)
	})

	r.POST("/user/phone", AuthMiddleware(), func(c *gin.Context) {
		var phoneInfo PhoneInfo
		if err := c.ShouldBindJSON(&phoneInfo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
			return
		}

		// Извлекаем информацию о пользователе из токена
		userInfo, _ := c.Get("userInfo")
		claims, _ := userInfo.(*Claims)

		// Проверяем, существует ли уже такой номер в базе данных
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM phones WHERE phone = ?", phoneInfo.Phone).Scan(&exists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error checking phone existence"})
			return
		}
		if exists > 0 {
			c.JSON(http.StatusConflict, gin.H{"message": "Phone number already exists"})
			return
		}

		// Добавляем информацию о телефоне в базу данных
		stmt, err := db.Prepare("INSERT INTO phones (user_id, phone, description, is_fax) VALUES (?, ?, ?, ?)")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not prepare SQL statement"})
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(claims.Id, phoneInfo.Phone, phoneInfo.Description, phoneInfo.IsFax)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not execute SQL statement"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Phone number added successfully"})
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
