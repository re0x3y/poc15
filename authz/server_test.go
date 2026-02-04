package authz

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	server := NewServer(&Config{
		Issuer: "https://authz.test.nl",
	})
	if server == nil {
		t.Fatal("Server should not be nil")
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	server := NewServer(&Config{
		Issuer:         "https://authz.test.nl",
		AuthCodeTTL:    10 * time.Minute,
		AccessTokenTTL: 1 * time.Hour,
	})

	codeVerifier := "test-verifier-12345678901234567890123456789012"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	auth, err := server.CreateAuthorization(
		"test-client",
		"https://app.test.nl/callback",
		"openid",
		"user123",
		codeChallenge,
	)
	if err != nil {
		t.Fatalf("Failed to create authorization: %v", err)
	}
	if auth.Code == "" {
		t.Error("Authorization code should not be empty")
	}

	tokenResp, err := server.ExchangeAuthorizationCode(
		auth.Code,
		"test-client",
		"https://app.test.nl/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("Failed to exchange code: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Error("Access token should not be empty")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("Expected Bearer token type, got %s", tokenResp.TokenType)
	}

	introspection, err := server.IntrospectToken(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("Failed to introspect token: %v", err)
	}
	if !introspection["active"].(bool) {
		t.Error("Token should be active")
	}
}

func TestInvalidCodeVerifier(t *testing.T) {
	server := NewServer(&Config{Issuer: "https://authz.test.nl"})

	codeVerifier := "correct-verifier-123456789012345678901234"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	auth, _ := server.CreateAuthorization(
		"client",
		"https://app.nl/cb",
		"openid",
		"user",
		codeChallenge,
	)

	_, err := server.ExchangeAuthorizationCode(
		auth.Code,
		"client",
		"https://app.nl/cb",
		"wrong-verifier-12345678901234567890123456",
	)
	if err != ErrInvalidCodeVerifier {
		t.Errorf("Expected ErrInvalidCodeVerifier, got: %v", err)
	}
}

func TestAuthorizationDecision(t *testing.T) {
	server := NewServer(&Config{Issuer: "https://authz.test.nl"})

	auth, _ := server.CreateAuthorization("client", "https://app.nl/cb", "openid", "user123", "")
	tokenResp, _ := server.ExchangeAuthorizationCode(auth.Code, "client", "https://app.nl/cb", "")

	decision, err := server.PerformAuthorizationDecision(tokenResp.AccessToken, "ImagingStudy", "read")
	if err != nil {
		t.Fatalf("Authorization decision failed: %v", err)
	}
	if decision.Decision != "Permit" {
		t.Errorf("Expected Permit, got %s", decision.Decision)
	}
}
