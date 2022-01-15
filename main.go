package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {

	var err error

	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})

	if err != nil {
		panic("fail to connect database.")
	}

	db.AutoMigrate(&Anime{})

	handler := newHandler(db)

	r := gin.New()

	r.POST("/login", loginHandler)

	protected := r.Group("/", authorizationMiddleware)

	protected.GET("/animes", handler.listAnimesHandler)
	protected.POST("/animes", handler.createAnimesHandler)
	protected.DELETE("/animes/:id", handler.deleteAnimesHandler)

	r.Run()
}

type Handler struct {
	db *gorm.DB
}

func newHandler(db *gorm.DB) *Handler {
	return &Handler{db}
}

type Anime struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

func (h *Handler) listAnimesHandler(c *gin.Context) {

	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var animes []Anime

	if result := h.db.Find(&animes); result.Error != nil {
		return
	}

	c.JSON(http.StatusOK, &animes)
}

func (h *Handler) createAnimesHandler(c *gin.Context) {
	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var anime Anime

	if err := c.BindJSON(&anime); err != nil {
		return
	}

	if result := h.db.Create(&anime); result.Error != nil {
		return
	}

	c.JSON(http.StatusCreated, anime)
}

func (h *Handler) deleteAnimesHandler(c *gin.Context) {
	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	id := c.Param("id")

	if result := h.db.Delete(&Anime{}, id); result.Error != nil {
		return
	}

	c.Status(http.StatusNoContent)
}

var db *gorm.DB

func validateToken(token string) error {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte("MySignature"), nil
	})

	return err
}

func authorizationMiddleware(c *gin.Context) {
	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

func loginHandler(c *gin.Context) {
	//implement login logic here

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	ss, err := token.SignedString([]byte("MySignature"))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token": ss,
	})
}
