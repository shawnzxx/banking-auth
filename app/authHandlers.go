package app

import (
	"encoding/json"
	"net/http"

	"github.com/shawnzxx/banking-auth/dto"
	"github.com/shawnzxx/banking-auth/service"
	"github.com/shawnzxx/banking-lib/logger"
)

type AuthHandlers struct {
	service service.AuthService
}

func (h AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		loginResponse, err := h.service.Login(loginRequest)
		if err != nil {
			writeResponse(w, err.Code, err.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, loginResponse)
		}
	}
}

/*
	Sample URL string

GET http://localhost:8181/auth/verify?token=aaaa.bbbb.cccc&routeName=NewTransaction&customer_id=2000&account_id=95470
*/
func (h AuthHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	// converting from Query to map type
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		isAuthorized, appError := h.service.Verify(urlParams)
		if appError != nil {
			writeResponse(w, http.StatusForbidden, notAuthorizedResponse())
		} else {
			if isAuthorized {
				writeResponse(w, http.StatusOK, authorizedResponse())
			} else {
				writeResponse(w, http.StatusForbidden, notAuthorizedResponse())
			}
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse())
	}
}

func writeResponse(w http.ResponseWriter, httpCode int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}

func notAuthorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": false}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}
