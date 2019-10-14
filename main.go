package main

import (
	"github.com/YudhaBhakti95/belajargolang/controller"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.POST("/register", controller.RegisterHandler)
	router.POST("/login", controller.LoginHandler)
	router.GET("/profile", controller.ProfileHandler)
	router.Run()
}
