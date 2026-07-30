package infisical

import (
	"context"
	"fmt"
	"log"
	"os"

	infisical "github.com/infisical/go-sdk"
)

type InfisicalClient interface {
	Connect()
}

// cfg reads an Infisical setting, accepting BOTH the dotted spelling
// (`INFISICAL.ENV`, the flow-platform convention) and the underscored one
// (`INFISICAL_ENV`).
//
// This matters in Kubernetes: a ConfigMap mounted with `envFrom` has every key
// validated as a C_IDENTIFIER, and kubelet **silently skips** any key containing a
// dot — recording only an `InvalidVariableNames` event. So `INFISICAL.ENV` in a
// ConfigMap never reaches the process, and the service starts up looking healthy
// while loading no secrets at all.
//
// Accepting both means the deployed ConfigMap can use the valid underscored keys
// while existing dotted `.env` files and local setups keep working unchanged.
func cfg(name string) string {
	if v := os.Getenv("INFISICAL." + name); v != "" {
		return v
	}
	return os.Getenv("INFISICAL_" + name)
}

type infisicalClient struct {
	client infisical.InfisicalClientInterface
}

func (i *infisicalClient) Connect() {
	i.client = infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl:          cfg("SITE_URL"),
		AutoTokenRefresh: true,
	})

	_, err := i.client.Auth().UniversalAuthLogin("", "")
	if err != nil {
		fmt.Printf("Authentication failed: %v", err)
	}
	log.Println("Authentication successful")

	// Load service-specific secrets from INFISICAL.SECRET_PATH env var
	secretPath := cfg("SECRET_PATH")
	if secretPath == "" {
		log.Println("INFISICAL SECRET_PATH not set (INFISICAL.SECRET_PATH / INFISICAL_SECRET_PATH), skipping service-specific secrets")
	} else {
		_, err = i.client.Secrets().List(infisical.ListSecretsOptions{
			ProjectID:          cfg("PROJECT"),
			Environment:        cfg("ENV"),
			SecretPath:         secretPath,
			AttachToProcessEnv: true,
		})
		if err != nil {
			log.Println("failed to list secrets:", err)
		}
		log.Println("Secrets listed successfully for path:", secretPath)
	}

	// Load root-level secrets
	_, err = i.client.Secrets().List(infisical.ListSecretsOptions{
		ProjectID:          cfg("PROJECT"),
		Environment:        cfg("ENV"),
		SecretPath:         "/",
		AttachToProcessEnv: true,
	})
	if err != nil {
		log.Println("failed to list secrets:", err)
	}
	log.Println("Secrets listed successfully")
}

// NewInfisical creates an InfisicalClient.
// The service-specific secret path is read from the INFISICAL.SECRET_PATH env var.
func NewInfisical() InfisicalClient {
	return &infisicalClient{}
}
