package utils

import (
	"encoding/json"
	"log"
)

// ToJSONString converts any interface to a JSON string representation.
func ToJSONString(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to marshal object to JSON string: %v", err)
		return ""
	}
	return string(b)
}

// MapToStruct converts a map to a struct using JSON marshalling.
func MapToStruct(m map[string]interface{}, s interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, s)
}
