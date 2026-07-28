package models

// KeycloakUser is the identity claim set the Echo middleware binds from a verified
// access token. Copied verbatim from flow-system so the ported middleware keeps its
// exact behavior while everyflow-system stays standalone (no flow-system dependency).
// NOTE: this is the Keycloak-shaped claim set; if/when the everyflow edge moves fully
// to Openfort JWTs, this + pkg/middleware get reworked (see pkg/auth for the Connect
// Openfort interceptor already in use by the services).
type User struct {
	ID            string `json:"sub,omitempty"`
	Name          string `json:"name,omitempty"`
	Username      string `json:"preferred_username,omitempty"`
	Email         string `json:"email,omitempty"`
	Audience      string `json:"audience"`
	EmailVerified bool   `json:"emailVerified,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
}
