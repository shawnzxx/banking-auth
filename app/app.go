package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/shawnzxx/banking-auth/domain"
	"github.com/shawnzxx/banking-auth/service"
)

func sanityCheck() {
	if os.Getenv("SERVER_NAME") == "" ||
		os.Getenv("PORT") == "" ||
		os.Getenv("DATABASE_URL") == "" {
		log.Fatal("Environment variables not defined...")
	}
}

func Start() {
	// all the environment variables check
	sanityCheck()

	router := mux.NewRouter()

	db := newDB()
	authRepo := domain.NewAuthRepositoryDb(db)
	authService := service.NewDefaultAuthService(authRepo, domain.NewRolePermissions())

	ah := AuthHandlers{authService}

	router.HandleFunc("/auth/login", ah.Login).
		Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).
		Methods(http.MethodGet)

	server := os.Getenv("SERVER_NAME")
	port := os.Getenv("PORT")
	log.Printf("server start at %s:%s", server, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", server, port), router))
}

func newDB() *sqlx.DB {
	// or we can use this way to connect database
	// db, err := sqlx.Connect("postgres", "user=banking dbname=banking sslmode=disable")
	db, err := sqlx.Connect("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalln(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	return db
}
