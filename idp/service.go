// Package idp provides the Identity Provider service for token exchange.
package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/reoxey/poc15/models"
)

// Default configuration values.
const (
	defaultAuthTokenTTL   = 5 * time.Minute
	defaultAccessTokenTTL = 1 * time.Hour
	rsaKeyBits            = 2048
)

// Common errors.
var (
	ErrInvalidAccessToken = errors.New("invalid or expired access token")
	ErrTokenNotFound      = errors.New("access token not found")
)

// Config holds the IDP service configuration.
type Config struct {
	Issuer         string
	AuthTokenTTL   time.Duration
	AccessTokenTTL time.Duration
}

// Service represents the Identity Provider service.
type Service struct {
	mu sync.RWMutex

	issuer         string
	authTokenTTL   time.Duration
	accessTokenTTL time.Duration

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	accessTokens map[string]*storedToken
}

type storedToken struct {
	claims    *models.DeziClaims
	expiresAt time.Time
}

// NewService creates a new IDP service.
func NewService(cfg *Config) (*Service, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	authTokenTTL := cfg.AuthTokenTTL
	if authTokenTTL == 0 {
		authTokenTTL = defaultAuthTokenTTL
	}

	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}

	return &Service{
		issuer:         cfg.Issuer,
		authTokenTTL:   authTokenTTL,
		accessTokenTTL: accessTokenTTL,
		privateKey:     privateKey,
		publicKey:      &privateKey.PublicKey,
		accessTokens:   make(map[string]*storedToken),
	}, nil
}

// StoreAccessToken stores an access token with its associated DEZI claims.
func (s *Service) StoreAccessToken(accessToken string, claims *models.DeziClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessTokens[accessToken] = &storedToken{
		claims:    claims,
		expiresAt: time.Now().Add(s.accessTokenTTL),
	}
}

// ExchangeToken exchanges an access token for an auth-token.
func (s *Service) ExchangeToken(accessToken, targetResource string) (string, error) {
	s.mu.RLock()
	stored, exists := s.accessTokens[accessToken]
	s.mu.RUnlock()

	if !exists {
		return "", ErrTokenNotFound
	}

	if time.Now().After(stored.expiresAt) {
		s.mu.Lock()
		delete(s.accessTokens, accessToken)
		s.mu.Unlock()
		return "", ErrInvalidAccessToken
	}

	return s.generateAuthToken(stored.claims, targetResource)
}

// generateAuthToken creates a signed auth-token JWT.
func (s *Service) generateAuthToken(deziClaims *models.DeziClaims, targetResource string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.authTokenTTL)

	claims := &models.AuthTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   deziClaims.BIGNumber,
			Audience:  jwt.ClaimStrings{targetResource},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		BIGNumber:        deziClaims.BIGNumber,
		BIGRoleCode:      deziClaims.BIGRoleCode,
		URA:              deziClaims.URA,
		OrganizationName: deziClaims.OrganizationName,
		GivenName:        deziClaims.GivenName,
		FamilyName:       deziClaims.FamilyName,
		AuthTime:         deziClaims.AuthTime,
		TargetResource:   targetResource,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing auth token: %w", err)
	}

	return tokenString, nil
}

// ValidateAuthToken validates an auth-token and returns its claims.
func (s *Service) ValidateAuthToken(tokenString string) (*models.AuthTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.AuthTokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	claims, ok := token.Claims.(*models.AuthTokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// GetPublicKey returns the public key for token verification.
func (s *Service) GetPublicKey() *rsa.PublicKey {
	return s.publicKey
}
