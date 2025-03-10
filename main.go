package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionStoken  string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)

	fmt.Println("Server is running on port 8080")
	http.ListenAndServe(":8080", nil)

}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", er)
		return
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "Username already exists", er)
		return
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
		SessionStoken:  "",
		CSRFToken:      "",
	}

	fmt.Fprintln(w, "User created successfully")
	logUsers()

}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	user.SessionStoken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login successful")
	logUsers()

}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	// Clear cookie

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	// Clear tokens from database

	username := r.FormValue("username")
	user := users[username]
	user.SessionStoken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logout successful")
}

func protected(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful. Welcome %s!\n", username)
}
