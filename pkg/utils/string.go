package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
	charsetLength := len(charset)

	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}

	password := make([]byte, length)

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			return "", fmt.Errorf("error generating random index: %v", err)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}

func GenerateWordLikePassword(length int) (string, error) {
	syllables := []string{"ba", "be", "bi", "bo", "bu", "da", "de", "di", "do", "du", "fa", "fe", "fi", "fo", "fu", "ga", "ge", "gi", "go", "gu"}
	symbols := "!@#$%^&*"

	if length < 4 {
		return "", fmt.Errorf("length must be at least 4")
	}

	password := ""
	for len(password) < length {
		sIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(syllables))))
		if err != nil {
			return "", err
		}
		password += syllables[sIndex.Int64()]
		if len(password) < length {
			symChance, err := rand.Int(rand.Reader, big.NewInt(2))
			if err != nil {
				return "", err
			}
			if symChance.Int64() == 1 {
				symIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(symbols))))
				if err != nil {
					return "", err
				}
				password += string(symbols[symIndex.Int64()])
			}
		}
	}
	if len(password) > length {
		password = password[:length]
	}
	return password, nil
}
