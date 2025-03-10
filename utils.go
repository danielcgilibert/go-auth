package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func logUsers() {

	//log struct users
	for k, v := range users {
		fmt.Println("Username:", k)
		fmt.Println("Hashed Password:", v.HashedPassword)
		fmt.Println("Session Token:", v.SessionStoken)
		fmt.Println("CSRF Token:", v.CSRFToken)
		fmt.Println()

	}
}
