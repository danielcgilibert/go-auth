package main

import (
	"errors"
	"net/http"
)

var ErrAuth = errors.New("authentication failed")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return ErrAuth
	}

	// Get the session token from the cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionStoken {
		return ErrAuth
	}

	// Get the CSRF token from the header
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" || csrf != user.CSRFToken {
		return ErrAuth
	}

	return nil

}
