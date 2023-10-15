package domain

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shawnzxx/banking-lib/logger"
	"go.uber.org/zap"
)

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Expiry     int64    `json:"exp"`
	Role       string   `json:"role"`
}

func (c Claims) IsUserRole() bool {
	return c.Role == "user"
}

func BuildClaimsFromJwtMapClaims(mapClaims jwt.MapClaims) (*Claims, error) {
	bytes, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, err
	}
	var c Claims
	err = json.Unmarshal(bytes, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (c Claims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	// if customer_id is present in the url params then check if it is present in the token claims
	if c.CustomerId != urlParams["customer_id"] {
		logger.Error("customer_id not matched")
		return false
	}

	// if account_id is present in the url params then check if it is present in the token claims
	accountId, ok := urlParams["account_id"]
	if ok && !c.IsValidAccountId(accountId) {
		urlParamsStr, err := json.Marshal(urlParams)
		if err != nil {
			logger.Error("can not marshal url params", zap.Error(err))
			return false
		}
		logger.Error("account_id not matched", zap.String("urlParams", string(urlParamsStr)))
		return false
	}
	return true
}

func (c Claims) IsValidAccountId(accountId string) bool {
	accountFound := false
	if accountId != "" {
		for _, a := range c.Accounts {
			if a == accountId {
				accountFound = true
				break
			}
		}
	}
	return accountFound
}
