package utils

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
)

func GetValidationErrors(err error) []string {
	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		return []string{err.Error()}
	}

	arr := make([]string, 0)
	for _, err := range validationErrors {
		arr = append(arr, fmt.Sprintf("%s is %s", err.Field(), err.Tag()))
	}

	return arr
}
