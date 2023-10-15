package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/shawnzxx/banking-auth/domain"
	"github.com/shawnzxx/banking-auth/dto"
	"github.com/shawnzxx/banking-lib/errs"
	"github.com/shawnzxx/banking-lib/logger"
	"go.uber.org/zap"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.CustomError)
	Verify(map[string]string) (bool, *errs.CustomError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Verify(urlParams map[string]string) (bool, *errs.CustomError) {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenString(urlParams["token"]); err != nil {
		return false, errs.NewAuthError("invalid token")
	} else {
		/*
			check the validity of the token, this verifies expiration time
			and signature of the token
		*/
		if jwtToken.Valid {
			// type case the token claims to jwt.MapClaims
			mapClaims := jwtToken.Claims.(jwt.MapClaims)
			// convert the token claims to Claims struct
			if claims, err := domain.BuildClaimsFromJwtMapClaims(mapClaims); err != nil {
				return false, errs.NewAuthError("invalid token")
			} else {
				// if Role is user then check if the account_id and customer_id equal to the url params
				if claims.IsUserRole() {
					if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
						return false, errs.NewAuthError("invalid token")
					}
				}
				// verify of the role is authorized to use the route
				isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
				return isAuthorized, nil
			}
		} else {
			return false, errs.NewAuthError("invalid token")
		}
	}
}

func jwtTokenString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HmacSampleSecret), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.CustomError) {
	login, appErr := s.repo.FindBy(req)
	logger.Info("login successful", zap.Any("obj", login))
	if appErr != nil {
		return nil, appErr
	}
	token, appErr := login.GenerateToken()
	if appErr != nil {
		return nil, appErr
	}
	logger.Info("token generated", zap.Any("obj", token))
	return &dto.LoginResponse{AccessToken: *token}, nil
}

func NewDefaultAuthService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
