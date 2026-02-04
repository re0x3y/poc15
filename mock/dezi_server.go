// Package mock provides mock implementations for testing.
package mock

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/reoxey/poc15/models"
)

// DeziServer is a mock DEZI OpenID Connect server for testing.
type DeziServer struct {
	Issuer string
}

// NewDeziServer creates a new mock DEZI server.
func NewDeziServer(issuer string) *DeziServer {
	return &DeziServer{Issuer: issuer}
}

// RegisterHandlers registers HTTP handlers for the mock server.
func (s *DeziServer) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", s.HandleDiscovery)
	mux.HandleFunc("/authorize", s.HandleAuthorize)
	mux.HandleFunc("/token", s.HandleToken)
	mux.HandleFunc("/userinfo", s.HandleUserInfo)
	mux.HandleFunc("/jwks", s.HandleJWKS)
}

// HandleDiscovery handles OIDC discovery requests.
func (s *DeziServer) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	config := models.OIDCConfig{
		Issuer:                 s.Issuer,
		AuthorizationEndpoint:  s.Issuer + "/authorize",
		TokenEndpoint:          s.Issuer + "/token",
		UserInfoEndpoint:       s.Issuer + "/userinfo",
		JWKSUri:                s.Issuer + "/jwks",
		ScopesSupported:        []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// HandleAuthorize handles authorization requests.
func (s *DeziServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	http.Redirect(w, r, redirectURI+"?code=mock-auth-code-123&state="+state, http.StatusFound)
}

// HandleToken handles token requests.
func (s *DeziServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	now := time.Now()

	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": s.Issuer,
		"sub": "mock-user-123",
		"aud": r.FormValue("client_id"),
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
	})
	idTokenString, _ := idToken.SignedString([]byte("mock-secret"))

	response := models.TokenResponse{
		AccessToken: "mock-access-token-" + time.Now().Format("20060102150405"),
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IDToken:     idTokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleUserInfo handles userinfo requests.
func (s *DeziServer) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	claims := models.DeziClaims{
		BIGNumber:        "49001234567",
		BIGRoleCode:      "01.015",
		URA:              "90001234",
		OrganizationName: "Mock Hospital Amsterdam",
		GivenName:        "Jan",
		FamilyName:       "de Vries",
		Email:            "j.devries@mockhospital.nl",
		AuthTime:         time.Now().Unix(),
	}
	claims.Subject = "mock-user-123"
	claims.Issuer = s.Issuer

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

// HandleJWKS handles JWKS requests.
func (s *DeziServer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]any{
		"keys": []map[string]any{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
