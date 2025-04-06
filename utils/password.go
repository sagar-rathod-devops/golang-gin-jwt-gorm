package utils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("could not hash password %w", err)
	}
	return string(hashedPassword), nil
}

func VerifyPassword(hashedPassword string, candidatePassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(candidatePassword))
}

// func ValidateToken(token string, publicKey string) (interface{}, error) {
// 	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not decode: %w", err)
// 	}

// 	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)

// 	if err != nil {
// 		return "", fmt.Errorf("validate: parse key: %w", err)
// 	}

// 	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
// 		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
// 			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
// 		}
// 		return key, nil
// 	})

// 	if err != nil {
// 		return nil, fmt.Errorf("validate: %w", err)
// 	}

// 	claims, ok := parsedToken.Claims.(jwt.MapClaims)
// 	if !ok || !parsedToken.Valid {
// 		return nil, fmt.Errorf("validate: invalid token")
// 	}

// 	return claims["sub"], nil
// }
