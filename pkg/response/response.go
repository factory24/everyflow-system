package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jszwec/csvutil"
	"github.com/labstack/echo/v4"
)

type ApiResponse[T any] struct {
	Success   bool     `json:"success,omitempty"`
	Timestamp int64    `json:"timestamp,omitempty"`
	Message   string   `json:"message"`
	Errors    []string `json:"errors,omitempty"`
	Data      T        `json:"data"`
}

// FirstError safely returns the first error string from an API response, falling
// back to defaultMsg when the Errors slice is nil or empty.
// Use this everywhere instead of res.Errors[0] to prevent index-out-of-range
// panics when a non-2xx response arrives with an empty error body.
func FirstError[T any](res *ApiResponse[T], defaultMsg string) string {
	if res != nil && len(res.Errors) > 0 {
		return res.Errors[0]
	}
	return defaultMsg
}

func NewApiResponse() *ApiResponse[any] {
	return &ApiResponse[any]{
		Success:   true,
		Timestamp: time.Now().UnixMilli(),
		Errors:    []string{},
		Data:      nil,
	}
}

func NewApiResponseWithData[T any](data T, message ...string) *ApiResponse[T] {
	msg := "success"
	if len(message) > 0 {
		msg = message[0]
	}
	return &ApiResponse[T]{
		Success:   true,
		Timestamp: time.Now().UnixMilli(),
		Message:   msg,
		Data:      data,
	}
}

func NewApiResponseWithMessage(message string) *ApiResponse[any] {
	return &ApiResponse[any]{
		Success:   true,
		Timestamp: time.Now().UnixMilli(),
		Message:   message,
	}
}

func (t ApiResponse[T]) String() string {
	jsonBytes, _ := json.Marshal(t)
	return string(jsonBytes)
}

type ErrorResponse struct {
	Success   bool     `json:"success" example:"false"`
	Timestamp int64    `json:"timestamp" example:"1719500184656"`
	Message   string   `json:"message,omitempty" `
	Errors    []string `json:"errors,omitempty"`
}

func NewErrorResponse(errors ...string) *ErrorResponse {
	return &ErrorResponse{
		Success:   false,
		Timestamp: time.Now().UnixMilli(),
		Errors:    errors,
	}
}

// Event is a generic structure for creating typed events to be sent.
type Event[T any] struct {
	Topic     string `json:"topic"`
	EventType string `json:"eventType"`
	Timestamp int64  `json:"timestamp"`
	Payload   T      `json:"payload"`
}

// EventHeader allows inspection of event metadata before unmarshalling the full payload.
type EventHeader struct {
	Topic     string          `json:"topic"`
	EventType string          `json:"eventType"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// NewEvent creates a new typed event, ready to be serialized and sent.
func NewEvent(topic, eventType string, payload any) *Event[any] {
	return &Event[any]{
		Topic:     topic,
		EventType: eventType,
		Timestamp: time.Now().UnixMilli(),
		Payload:   payload,
	}
}

// ParseEventHeader unmarshals raw bytes into an EventHeader.
func ParseEventHeader(data []byte) (*EventHeader, error) {
	var header EventHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("failed to parse event header: %w", err)
	}
	return &header, nil
}

// UnmarshalPayload unmarshals the raw payload from an EventHeader into a specific target struct.
func (h *EventHeader) UnmarshalPayload(target any) error {
	if len(h.Payload) == 0 || string(h.Payload) == "null" {
		return errors.New("event has no payload to unmarshal")
	}
	if err := json.Unmarshal(h.Payload, target); err != nil {
		return fmt.Errorf("failed to unmarshal event payload for type %T: %w", target, err)
	}
	return nil
}

func (h EventHeader) String() string {
	jsonBytes, _ := json.Marshal(h)
	return string(jsonBytes)
}

func (h *EventHeader) PrettyLog() {
	log.Println("============================== Consumer ===============================")
	log.Printf("Topic: %s", h.Topic)
	log.Printf("EventType: %s", h.EventType)
	log.Printf("Timestamp: %d", h.Timestamp)

	payloadStr, err := json.MarshalIndent(h.Payload, "", "  ")
	if err != nil {
		log.Printf("Failed to pretty-print payload: %v", err)
	} else {
		log.Printf("Payload:\n%s", payloadStr)
	}

	log.Println("==============================================================================")
}

func (h *EventHeader) RawLog() {
	raw, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal EventHeader: %v", err)
		return
	}
	log.Println("===== Raw EventHeader =====")
	log.Println(string(raw))
	log.Println("===========================")
}

func (e *Event[T]) Bytes() ([]byte, error) {
	return json.Marshal(e)
}

func (e *Event[T]) String() (string, error) {
	bytes, err := e.Bytes()
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

type ITCResponse struct {
	MenuContent string `json:"menuContent"`
	RequestType string `json:"requestType"`
}

func NewITCResponse(requestType string) *ITCResponse {
	return &ITCResponse{
		MenuContent: "",
		RequestType: requestType,
	}
}

type ArkeselResponse struct {
	Message         string `json:"message"`
	ContinueSession bool   `json:"continueSession"`
}

func NewArkeselResponse() *ArkeselResponse {
	return &ArkeselResponse{
		Message:         "",
		ContinueSession: false,
	}
}

func NewCSVExport(ctx echo.Context, Result any, fileName string) error {
	b, err := csvutil.Marshal(Result)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	ctx.Response().Header().Set(echo.HeaderContentType, "text/csv")
	ctx.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s.csv", fileName))

	tempFile, err := os.CreateTemp("", fileName+"*.csv")
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(b); err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if _, err := tempFile.Seek(0, 0); err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return ctx.Stream(http.StatusOK, "text/csv", tempFile)
}
