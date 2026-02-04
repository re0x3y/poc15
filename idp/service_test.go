package idp

import (
	"testing"
	"time"

	"github.com/reoxey/poc15/models"
)

func TestNewService(t *testing.T) {
	service, err := NewService(&Config{
		Issuer: "https://test-idp.example.nl",
	})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	if service == nil {
		t.Fatal("Service should not be nil")
	}
	if service.GetPublicKey() == nil {
		t.Error("Public key should not be nil")
	}
}

func TestStoreAndExchangeToken(t *testing.T) {
	service, err := NewService(&Config{
		Issuer:       "https://test-idp.example.nl",
		AuthTokenTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	claims := &models.DeziClaims{
		BIGNumber:        "49001234567",
		BIGRoleCode:      "01.015",
		URA:              "90001234",
		OrganizationName: "Test Hospital",
		GivenName:        "Jan",
		FamilyName:       "de Vries",
		AuthTime:         time.Now().Unix(),
	}

	accessToken := "test-access-token-123"
	service.StoreAccessToken(accessToken, claims)

	authToken, err := service.ExchangeToken(accessToken, "https://pacs.hospital.nl")
	if err != nil {
		t.Fatalf("Failed to exchange token: %v", err)
	}
	if authToken == "" {
		t.Error("Auth token should not be empty")
	}

	// Validate the auth token
	validatedClaims, err := service.ValidateAuthToken(authToken)
	if err != nil {
		t.Fatalf("Failed to validate auth token: %v", err)
	}
	if validatedClaims.BIGNumber != claims.BIGNumber {
		t.Errorf("BIG number mismatch: got %s, want %s", validatedClaims.BIGNumber, claims.BIGNumber)
	}
	if validatedClaims.TargetResource != "https://pacs.hospital.nl" {
		t.Errorf("Target resource mismatch: got %s", validatedClaims.TargetResource)
	}
}

func TestExchangeTokenNotFound(t *testing.T) {
	service, _ := NewService(&Config{Issuer: "https://test.nl"})

	_, err := service.ExchangeToken("nonexistent-token", "https://pacs.nl")
	if err != ErrTokenNotFound {
		t.Errorf("Expected ErrTokenNotFound, got: %v", err)
	}
}
