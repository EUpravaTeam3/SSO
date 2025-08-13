package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var sessions *mongo.Collection
var users *mongo.Collection
var appRoles *mongo.Collection

type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID string             `bson:"session_id"`
	Ucn       string             `bson:"ucn"`
	AppRoles  map[string]string  `bson:"roles"`
	ExpiresAt time.Time          `bson:"expires_at"`
}

type AppRole struct {
	ID   primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	App  string             `bson:"app" json:"app"`
	Role string             `bson:"role" json:"role"`
	Ucn  string             `bson:"ucn" json:"ucn"`
}

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Ucn      string             `bson:"ucn" json:"ucn"`
	Name     string             `bson:"name" json:"name"`
	Surname  string             `bson:"surname" json:"surname"`
	Email    string             `bson:"email" json:"email"`
	Address  string             `bson:"address" json:"address"`
	Password string             `bson:"password" json:"password"`
}

type UserDTO struct {
	ID      primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Ucn     string             `bson:"ucn" json:"ucn"`
	Name    string             `bson:"name" json:"name"`
	Surname string             `bson:"surname" json:"surname"`
	Email   string             `bson:"email" json:"email"`
	Address string             `bson:"address" json:"address"`
}

type UserHandler struct {
	logger *log.Logger
}

func NewUserHandler(l *log.Logger) *UserHandler {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://sso_db:27017"))
	if err != nil {
		panic(err)
	}

	db := client.Database("sso_db")
	sessions = db.Collection("sessions")
	users = db.Collection("users")
	appRoles = db.Collection("app_roles")

	return &UserHandler{l}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (u *UserHandler) RegisterUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user *User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.Password, _ = HashPassword(user.Password)

	result, err := users.InsertOne(ctx, &user)
	if err != nil {
		http.Error(c.Writer, err.Error(),
			http.StatusInternalServerError)
		fmt.Println(err)
		u.logger.Println(err)
		return
	}
	u.logger.Printf("Documents ID: %v\n", result.InsertedID)
	e := json.NewEncoder(c.Writer)
	e.Encode(result)
}

func (u *UserHandler) RegisterAppRoles(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var roles []AppRole

	if err := c.ShouldBindJSON(&roles); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	docs := make([]interface{}, len(roles))
	for i, r := range roles {
		docs[i] = r
	}

	result, err := appRoles.InsertMany(ctx, docs)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		fmt.Println(err)
		return
	}

	e := json.NewEncoder(c.Writer)
	e.Encode(result)
}

func (u *UserHandler) DeleteUser(c *gin.Context) {
	ucn := c.Param("ucn")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, errRole := appRoles.DeleteMany(ctx, bson.M{"ucn": ucn})
	if errRole != nil {
		http.Error(c.Writer, errRole.Error(),
			http.StatusInternalServerError)
		u.logger.Println(errRole)
	}

	_, errUser := users.DeleteOne(ctx, bson.D{{Key: "ucn", Value: ucn}})
	if errUser != nil {
		http.Error(c.Writer, errUser.Error(),
			http.StatusInternalServerError)
		u.logger.Println(errUser)
	}
}

func (u *UserHandler) Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var creds struct {
		Ucn      string `json:"ucn"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var user *User

	errUser := users.FindOne(context.Background(), bson.M{"ucn": creds.Ucn}).Decode(&user)
	if errUser != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user does not exist"})
		return
	}

	if !CheckPasswordHash(creds.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect password"})
		return
	}

	filter := bson.M{"ucn": bson.M{"$regex": user.Ucn, "$options": "i"}}

	cursor, err := appRoles.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)

	var appRoles []AppRole

	if err = cursor.All(ctx, &appRoles); err != nil {
		log.Fatal(err)
	}

	m := make(map[string]string)

	for i := 0; i < len(appRoles); i++ {
		m[appRoles[i].App] = appRoles[i].Role
	}

	sessionID := primitive.NewObjectID().Hex()

	// Store session in MongoDB
	sess := Session{
		SessionID: sessionID,
		Ucn:       creds.Ucn,
		AppRoles:  m,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	_, errSession := sessions.InsertOne(context.Background(), sess)
	if errSession != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save session"})
		return
	}

	var userDTO UserDTO

	userDTO.ID = user.ID
	userDTO.Email = user.Email
	userDTO.Name = user.Name
	userDTO.Surname = user.Surname
	userDTO.Ucn = user.Ucn
	userDTO.Address = user.Address

	// Set cookie shared across subdomains
	c.SetCookie("SESSION_ID", sessionID, 3600, "/", ".localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"user": userDTO})

}

func (u *UserHandler) ReadAll(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sessionsArray []Session

	sessionsCursor, err := sessions.Find(ctx, bson.M{})
	if err != nil {
		u.logger.Println(err)
		return
	}

	if err = sessionsCursor.All(ctx, &sessionsArray); err != nil {
		http.Error(c.Writer, err.Error(),
			http.StatusInternalServerError)
		u.logger.Fatal(err)
		return
	}

	e := json.NewEncoder(c.Writer)
	e.Encode(sessionsArray)
	if err != nil {
		http.Error(c.Writer, err.Error(),
			http.StatusInternalServerError)
		u.logger.Fatal("Unable to convert to json :", err)
		return
	}
}

func (u *UserHandler) Authorize(c *gin.Context) {
	sessionID, err := c.Cookie("SESSION_ID")
	app := c.Param("app")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
		return
	}

	// Find session in MongoDB and check expiration
	var sess Session
	err = sessions.FindOne(context.Background(), bson.M{"session_id": sessionID}).Decode(&sess)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	if time.Now().After(sess.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"role": sess.AppRoles[app]})
}

func (u *UserHandler) Logout(c *gin.Context) {
	sessionID, err := c.Cookie("SESSION_ID")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
		fmt.Println(err)
		return
	}

	_, errSession := sessions.DeleteOne(context.Background(), bson.D{{Key: "session_id", Value: sessionID}})
	if errSession != nil {
		http.Error(c.Writer, errSession.Error(),
			http.StatusInternalServerError)
		u.logger.Println(errSession)
		fmt.Println(errSession)
	}

	c.SetCookie("SESSION_ID", "", -1, "/", ".localhost", false, true)
}

func (u *UserHandler) CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := map[string]bool{
		"http://localhost:4200": true,
		"http://localhost:8084": true,
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowedOrigins[origin] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
