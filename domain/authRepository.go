package domain

import (
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/shawnzxx/banking-auth/dto"
	"github.com/shawnzxx/banking-lib/errs"
	"github.com/shawnzxx/banking-lib/logger"
)

type AuthRepository interface {
	FindBy(dto.LoginRequest) (*Login, *errs.CustomError)
}

type AuthRepositoryDb struct {
	db *sqlx.DB
}

func NewAuthRepositoryDb(db *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{db: db}
}

func (a AuthRepositoryDb) FindBy(req dto.LoginRequest) (*Login, *errs.CustomError) {
	var login Login
	sqlQuery := `select u.username, u.customer_id, u.role, string_agg(a.id::text,',') as account_ids from users u
					left join accounts a
					on a.customer_id = u.customer_id
					where u.username = $1 and u.password = $2
					group by u.username, u.customer_id, u.role;`
	err := a.db.Get(&login, sqlQuery, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.NewAuthError("invalid credentials")
		} else {
			logger.Error("Error while scanning login " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &login, nil
}
