package domain

import (
	"database/sql"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shawnzxx/banking-lib/errs"
	"github.com/shawnzxx/banking-lib/logger"
)

const AccessTokenDuration = time.Hour
const HmacSampleSecret = "THIS_IS_A_SECRET"

type Login struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	AccountIds sql.NullString `db:"account_ids"`
	Role       string         `db:"role"`
}

func (l Login) GenerateToken() (*string, *errs.CustomError) {
	var claims jwt.MapClaims
	if l.AccountIds.Valid && l.CustomerId.Valid {
		claims = l.claimsForUser()
	} else {
		claims = l.claimsForAdmin()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte((HmacSampleSecret)))
	if err != nil {
		logger.Error("Error while signing token " + err.Error())
		return nil, errs.NewUnexpectedError("cannot generate token")
	}
	return &signedToken, nil
}

func (l Login) claimsForUser() jwt.MapClaims {
	accounts := strings.Split(l.AccountIds.String, ",")
	return jwt.MapClaims{
		"customer_id": l.CustomerId.String,
		"username":    l.Username,
		"role":        l.Role,
		"accounts":    accounts,
		"exp":         time.Now().Add(AccessTokenDuration).Unix(),
	}
}

func (l Login) claimsForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"username": l.Username,
		"role":     l.Role,
		"exp":      time.Now().Add(AccessTokenDuration).Unix(),
	}
}
