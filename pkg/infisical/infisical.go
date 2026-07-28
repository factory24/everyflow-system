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

type infisicalClient struct {
	client infisical.InfisicalClientInterface
}

func (i *infisicalClient) Connect() {
	i.client = infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl:          os.Getenv("INFISICAL.SITE_URL"),
		AutoTokenRefresh: true,
	})

	_, err := i.client.Auth().UniversalAuthLogin("", "")
	if err != nil {
		fmt.Printf("Authentication failed: %v", err)
	}
	log.Println("Authentication successful")

	// Load service-specific secrets from INFISICAL.SECRET_PATH env var
	secretPath := os.Getenv("INFISICAL.SECRET_PATH")
	if secretPath == "" {
		log.Println("INFISICAL.SECRET_PATH not set, skipping service-specific secrets")
	} else {
		_, err = i.client.Secrets().List(infisical.ListSecretsOptions{
			ProjectID:          os.Getenv("INFISICAL.PROJECT"),
			Environment:        os.Getenv("INFISICAL.ENV"),
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
		ProjectID:          os.Getenv("INFISICAL.PROJECT"),
		Environment:        os.Getenv("INFISICAL.ENV"),
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
