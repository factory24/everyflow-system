package middleware

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/factory24/flow-system/pkg/models"
	"github.com/factory24/flow-system/pkg/response"
	"github.com/labstack/echo/v4"
)

var (
	AuthorizedPersonas = []string{"vendor", "agent"}
)

type EchoMiddleware interface {
	IsAuthorizedJWT(next echo.HandlerFunc) echo.HandlerFunc
	IsAuthorizedPersonas(next echo.HandlerFunc) echo.HandlerFunc
	IsAgent(next echo.HandlerFunc) echo.HandlerFunc
	IsVendor(next echo.HandlerFunc) echo.HandlerFunc
	GetUserClaims(ctx echo.Context) *models.KeycloakUser
	GetAccessToken(ctx echo.Context) string
	IsDistributor(next echo.HandlerFunc) echo.HandlerFunc
	IsRoot(next echo.HandlerFunc) echo.HandlerFunc
	IsUser(next echo.HandlerFunc) echo.HandlerFunc
	IsClientAuthenticated(next echo.HandlerFunc) echo.HandlerFunc
	SystemToken() (string, error)
}

type echoMiddleware struct {
	app *echo.Echo
}

func New(app *echo.Echo) EchoMiddleware {
	return &echoMiddleware{
		app: app,
	}
}

func (middleware *echoMiddleware) GetUserClaims(ctx echo.Context) *models.KeycloakUser {
	if ctx == nil {
		return nil
	}
	userClaim := ctx.Get("keycloakUser")
	if userClaim == nil {
		return nil
	}

	claims, ok := userClaim.(*models.KeycloakUser)
	if !ok {
		return nil
	}

	if claims.Role != "" {
		claims.IsStaff = true
	}
	return claims
}

func (middleware *echoMiddleware) GetAccessToken(ctx echo.Context) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	rawAccessToken := ctx.Request().Header.Get("Authorization")
	if rawAccessToken == "" {
		return ""
	}
	return rawAccessToken
}

func (middleware *echoMiddleware) SystemToken() (string, error) {
	token := os.Getenv("SYSTEM_TOKEN")
	if token == "" {
		return "", fmt.Errorf("SYSTEM_TOKEN environment variable not set")
	}
	return token, nil
}

func (middleware *echoMiddleware) IsUser(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if audience != "user" {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, only 'users' are allowed to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsDistributor(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if audience != "distributor" {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, only 'distributors' are allowed to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsAgent(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if audience != "agent" {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, only 'agents' are allowed to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsRoot(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if audience != "root" {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, only 'root' are allowed to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsVendor(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if audience != "vendor" {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, only 'vendors' are allowed to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsAuthorizedPersonas(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		apiResponse := response.NewApiResponse()
		userClaims := middleware.GetUserClaims(ctx)
		if userClaims == nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		audience := strings.ToLower(userClaims.Audience)

		if !slices.Contains(AuthorizedPersonas, audience) {
			apiResponse.Success = false
			apiResponse.Errors = []string{"sorry, you are not authorized to perform this task"}
			return ctx.JSON(http.StatusForbidden, apiResponse)
		}

		return next(ctx)
	}
}

// IsAuthorizedJWT accepts both human tokens (audience == our own KC.CLIENT_ID)
// and service/system tokens minted via ServiceIdentity (audience is the
// service's own account, not ours). It tries the strict human-audience check
// first; only on failure does it re-verify as a service token (signature +
// issuer only, audience unchecked) so a single middleware covers both cases —
// no separate "any" wrapper needed, and exactly one response is ever written.
func (middleware *echoMiddleware) IsAuthorizedJWT(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		var keycloakURL = fmt.Sprintf("%s/realms/%s", os.Getenv("KC.BASE_URL"), os.Getenv("KC.REALM"))
		var clientID = os.Getenv("KC.CLIENT_ID")

		rawAccessToken := ctx.Request().Header.Get("Authorization")
		if rawAccessToken == "" || !strings.HasPrefix(rawAccessToken, "Bearer ") {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Unauthorized"))
		}
		accessToken := strings.TrimPrefix(rawAccessToken, "Bearer ")

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{
			Timeout:   time.Duration(60) * time.Second,
			Transport: tr,
		}

		c := oidc.ClientContext(ctx.Request().Context(), client)
		provider, err := oidc.NewProvider(c, keycloakURL)
		if err != nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse(err.Error()))
		}

		idToken, humanErr := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(c, accessToken)
		if humanErr != nil {
			// Not a valid human-audience token — re-verify as a service token
			// (signature/issuer only; service tokens don't carry our clientID
			// as audience).
			var serviceErr error
			idToken, serviceErr = provider.Verifier(&oidc.Config{SkipClientIDCheck: true}).Verify(c, accessToken)
			if serviceErr != nil {
				return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse(humanErr.Error()))
			}

			var rawClaims map[string]interface{}
			if err := idToken.Claims(&rawClaims); err != nil {
				return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse(err.Error()))
			}

			// Optional: verify azp is in the allowed-service-clients list.
			allowedClients := os.Getenv("KC.ALLOWED_CLIENTS")
			if allowedClients != "" {
				azp, _ := rawClaims["azp"].(string)
				allowedList := strings.Split(allowedClients, ",")
				found := false
				for _, allowed := range allowedList {
					if strings.TrimSpace(allowed) == azp {
						found = true
						break
					}
				}
				if !found {
					return ctx.JSON(http.StatusForbidden, response.NewErrorResponse("service client not authorized"))
				}
			}

			// Service tokens carry the same claim shape as a human user (the
			// ServiceIdentity account is a real Keycloak user), so decode them
			// the same way and just note the source.
			user := new(models.KeycloakUser)
			if err := idToken.Claims(user); err != nil {
				return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse(err.Error()))
			}
			if user.Role == "" {
				user.Role = "service"
			}
			ctx.Set("keycloakUser", user)
			return next(ctx)
		}

		user := new(models.KeycloakUser)
		if err := idToken.Claims(user); err != nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse(err.Error()))
		}

		ctx.Set("keycloakUser", user)

		return next(ctx)
	}
}

func (middleware *echoMiddleware) IsClientAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		var keycloakURL = fmt.Sprintf("%s/realms/%s", os.Getenv("KC.BASE_URL"), os.Getenv("KC.REALM"))

		rawAccessToken := ctx.Request().Header.Get("Authorization")
		if rawAccessToken == "" || !strings.HasPrefix(rawAccessToken, "Bearer ") {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Partner Authentication Required"))
		}

		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Timeout: 60 * time.Second, Transport: tr}
		c := oidc.ClientContext(ctx.Request().Context(), client)
		provider, err := oidc.NewProvider(c, keycloakURL)
		if err != nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Auth provider error"))
		}

		verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		token := strings.TrimPrefix(rawAccessToken, "Bearer ")
		payload, err := verifier.Verify(c, token)
		if err != nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Invalid Partner Token"))
		}

		var rawClaims map[string]interface{}
		if err := payload.Claims(&rawClaims); err != nil {
			return ctx.JSON(http.StatusUnauthorized, response.NewErrorResponse("Failed to parse partner claims"))
		}

		businessID, _ := rawClaims["businessId"].(string)
		if businessID == "" {
			return ctx.JSON(http.StatusForbidden, response.NewErrorResponse("Token is missing Business Context"))
		}

		isSandbox := false
		if v, ok := rawClaims["isSandbox"]; ok {
			switch val := v.(type) {
			case bool:
				isSandbox = val
			case string:
				isSandbox = val == "true"
			}
		}

		user := &models.KeycloakUser{
			ID:         payload.Subject,
			BusinessId: businessID,
			Role:       "partner",
		}

		ctx.Set("keycloakUser", user)
		ctx.Set("isSandbox", isSandbox)
		return next(ctx)
	}
}
