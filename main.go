package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config/config.go - viper
var (
	keycloakURL   = os.Getenv("KEYCLOAK_URL")
	keycloakRealm = os.Getenv("KEYCLOAK_REALM")
	clientID      = os.Getenv("KEYCLOAK_CLIENT_ID")
	clientSecret  = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	cookieName    = "access_token"
	jwkSet        jwk.Set
	uploadPath    = "./uploads"
)

// keycloak init
func init() {
	var err error
	jwkURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, keycloakRealm)

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		jwkSet, err = jwk.Fetch(ctx, jwkURL)
		cancel()
		if err == nil {
			break
		}
		fmt.Printf("Attempt %d: Failed to fetch JWK Set: %v. Retrying...\n", i+1, err)
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to fetch JWK Set after 5 attempts: %v", err))
	}
}

// entrypoint
func main() {
	r := gin.Default()

	r.POST("/login", loginHandler)

	authorized := r.Group("/api/v1")
	//authorized.Use(authHeaderMiddleware(), authCookieMiddleware())
	authorized.Use(combinedAuthMiddleware())
	{
		authorized.POST("/upload", uploadFile)
		authorized.GET("/download/:filename", downloadFile)
		authorized.GET("/events", sseHandler)
	}

	err := r.Run(":8000")
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

// internal/middlewares
func combinedAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) == 2 && strings.ToLower(bearerToken[0]) == "bearer" {
				token := bearerToken[1]
				if validateToken(token) {
					c.Set("authenticated", true)
					c.Next()
					return
				}
			}
		}

		cookie, err := c.Request.Cookie(cookieName)
		if err == nil && validateToken(cookie.Value) {
			c.Set("authenticated", true)
			c.Next()
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		c.Abort()
	}
}

// internal/handlers/sse.go
func sseHandler(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	c.Stream(func(w io.Writer) bool {
		select {
		case <-c.Request.Context().Done():
			log.Println("SSE client disconnected")
			return false
		case <-ticker.C:
			message := `{"type":"PingPong", "payload":"Pong"}`
			c.SSEvent("message", message)
			return true
		}
	})
}

// internal/handlers/download.go
func downloadFile(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := filepath.Join(uploadPath, fileName)
	c.File(filePath)
}

// internal/handlers/upload.go
func uploadFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error uploading file"})
		return
	}

	filename := filepath.Join(uploadPath, file.Filename)
	if err := c.SaveUploadedFile(file, filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("File '%s' uploaded successfully", file.Filename)})
}

// internal/middlewares
//func authCookieMiddleware() gin.HandlerFunc {
//	return func(c *gin.Context) {
//		cookie, err := c.Request.Cookie(cookieName)
//		if err != nil {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Cookie not found"})
//			c.Abort()
//			return
//		}
//
//		if validateToken(cookie.Value) {
//			c.Set("authenticated", true)
//			c.Next()
//		} else {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
//			c.Abort()
//			return
//		}
//	}
//}

// internal/middlewares
//func authHeaderMiddleware() gin.HandlerFunc {
//	return func(c *gin.Context) {
//		authHeader := c.GetHeader("Authorization")
//		if authHeader == "" {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
//			c.Abort()
//			return
//		}
//
//		bearerToken := strings.Split(authHeader, " ")
//		if len(bearerToken) != 2 || strings.ToLower(bearerToken[0]) != "bearer" {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
//			c.Abort()
//			return
//		}
//
//		token := bearerToken[1]
//		if validateToken(token) {
//			c.Set("authenticated", true)
//			c.Next()
//		} else {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
//			c.Abort()
//			return
//		}
//	}
//}

// internal/handlers/login.go
func loginHandler(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokenSet, err := authenticateWithKeycloak(loginData.Username, loginData.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie(cookieName, tokenSet.AccessToken, int(time.Hour.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "access_token": tokenSet.AccessToken})
}

// KeycloakTokenSet pkg/keycloak/keycloak.go
type KeycloakTokenSet struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
}

// pkg/keycloak/keycloak.go
func authenticateWithKeycloak(username string, password string) (*KeycloakTokenSet, error) {
	data := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=password&username=%s&password=%s",
		clientID, clientSecret, username, password)

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		keycloakURL, keycloakRealm)
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to authenticate user")
	}

	var tokenSet KeycloakTokenSet
	if err := json.NewDecoder(resp.Body).Decode(&tokenSet); err != nil {
		return nil, err
	}

	return &tokenSet, nil
}

// pkg/keycloak/keycloak.go
func validateToken(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}
		key, found := jwkSet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		var publicKey interface{}
		err := key.Raw(&publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %v", err)
		}
		return publicKey, nil
	})

	if err != nil {
		fmt.Printf("Token validation error: %v\n", err)
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if aud, ok := claims["azp"].(string); !ok || aud != clientID {
			fmt.Println("Invalid audience")
			return false
		}

		//if iss, ok := claims["iss"].(string); !ok || iss != fmt.Sprintf("%s/realms/%s", keycloakURL, keycloakRealm) {
		//	fmt.Println("Invalid issuer")
		//	return false
		//}

		return true
	}

	return true
}
