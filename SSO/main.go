package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"sso/handlers"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "9090"
	}

	logger := log.New(os.Stdout, "[product-api] ", log.LstdFlags)

	userHandler := handlers.NewUserHandler(logger)

	router := gin.New()
	router.Use(userHandler.CORSMiddleware())

	router.POST("/user", userHandler.Login)
	router.GET("/user/:app", userHandler.Authorize)
	router.POST("/user/create", userHandler.RegisterUser)
	router.POST("/user/roles/create", userHandler.RegisterAppRoles)
	router.DELETE("/user/:ucn", userHandler.DeleteUser)
	router.POST("/user/logout", userHandler.Logout)
	router.GET("/user/sessions", userHandler.ReadAll)

	router.Run(":" + port)

	server := http.Server{
		Addr:         ":" + port,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	logger.Println("Server listening on port", port)

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			logger.Fatal(err)
		}
	}()

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, os.Kill)

	sig := <-sigCh
	logger.Println("Received terminate, graceful shutdown", sig)
}
