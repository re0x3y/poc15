package dicomweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/reoxey/poc15/authz"
	"github.com/reoxey/poc15/idp"
	"github.com/reoxey/poc15/internal/httputil"
	"github.com/reoxey/poc15/models"
)

// Server configuration constants.
const (
	defaultBearerTokenTTL  = 1 * time.Hour
	defaultCleanupInterval = 5 * time.Minute
	jwtBearerGrantType     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	dicomJSONContentType   = "application/dicom+json"
	defaultBearerSecret    = "dicomweb-secret-key-change-in-production"
)

// ImagingStudy represents a DICOM study metadata (exported for client use).
type ImagingStudy = models.ImagingStudy

// ServerConfig holds the DICOMweb server configuration.
type ServerConfig struct {
	BearerTokenTTL    time.Duration
	BearerTokenSecret string
	CleanupInterval   time.Duration
}

// Server represents a DICOMweb server (source system).
type Server struct {
	mu sync.RWMutex

	baseURL           string
	studies           map[string]*models.ImagingStudy
	bearerTokenSecret string
	cleanupInterval   time.Duration

	idpService  *idp.Service
	authzServer *authz.Server

	bearerTokens   map[string]*bearerTokenInfo
	bearerTokenTTL time.Duration
}

type bearerTokenInfo struct {
	authClaims *models.AuthTokenClaims
	expiresAt  time.Time
}

// NewServer creates a new DICOMweb server with default configuration.
func NewServer(baseURL string, idpService *idp.Service, authzServer *authz.Server) *Server {
	return NewServerWithConfig(baseURL, idpService, authzServer, nil)
}

// NewServerWithConfig creates a new DICOMweb server with custom configuration.
func NewServerWithConfig(baseURL string, idpService *idp.Service, authzServer *authz.Server, cfg *ServerConfig) *Server {
	if cfg == nil {
		cfg = &ServerConfig{
			BearerTokenTTL:    defaultBearerTokenTTL,
			BearerTokenSecret: defaultBearerSecret,
			CleanupInterval:   defaultCleanupInterval,
		}
	}

	if cfg.BearerTokenTTL == 0 {
		cfg.BearerTokenTTL = defaultBearerTokenTTL
	}
	if cfg.BearerTokenSecret == "" {
		cfg.BearerTokenSecret = defaultBearerSecret
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = defaultCleanupInterval
	}

	server := &Server{
		baseURL:           baseURL,
		studies:           make(map[string]*models.ImagingStudy),
		idpService:        idpService,
		authzServer:       authzServer,
		bearerTokens:      make(map[string]*bearerTokenInfo),
		bearerTokenTTL:    cfg.BearerTokenTTL,
		bearerTokenSecret: cfg.BearerTokenSecret,
		cleanupInterval:   cfg.CleanupInterval,
	}

	server.loadMockData()
	go server.cleanupExpiredBearerTokens()

	return server
}

func (s *Server) loadMockData() {
	studies := []*models.ImagingStudy{
		{
			StudyInstanceUID: "1.2.840.113619.2.55.3.123456789.123",
			PatientID:        "patient-001",
			StudyDate:        time.Date(2025, 12, 15, 0, 0, 0, 0, time.UTC),
			StudyDescription: "CT Thorax met contrast",
			Modality:         "CT",
			AccessionNumber:  "ACC001",
			NumberOfSeries:   3,
			NumberOfImages:   150,
		},
		{
			StudyInstanceUID: "1.2.840.113619.2.55.3.123456789.456",
			PatientID:        "patient-001",
			StudyDate:        time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
			StudyDescription: "X-Thorax AP",
			Modality:         "XR",
			AccessionNumber:  "ACC002",
			NumberOfSeries:   1,
			NumberOfImages:   2,
		},
		{
			StudyInstanceUID: "1.2.840.113619.2.55.3.123456789.789",
			PatientID:        "patient-002",
			StudyDate:        time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC),
			StudyDescription: "MRI Hersenen",
			Modality:         "MR",
			AccessionNumber:  "ACC003",
			NumberOfSeries:   5,
			NumberOfImages:   200,
		},
	}

	for _, study := range studies {
		s.studies[study.StudyInstanceUID] = study
	}
}

func (s *Server) cleanupExpiredBearerTokens() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for token, info := range s.bearerTokens {
			if now.After(info.expiresAt) {
				delete(s.bearerTokens, token)
			}
		}
		s.mu.Unlock()
	}
}

// RegisterHandlers registers HTTP handlers for the DICOMweb server.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/token", s.HandleToken)
	mux.HandleFunc("/studies", s.HandleQIDORS)
	mux.HandleFunc("/studies/", s.HandleWADORS)
}

// HandleToken handles OAuth 2.0 JWT Bearer Grant token requests (RFC7523).
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteBadRequest(w, "invalid_request", "Invalid form data")
		return
	}

	if grantType := r.FormValue("grant_type"); grantType != jwtBearerGrantType {
		httputil.WriteBadRequest(w, "unsupported_grant_type", "Only jwt-bearer grant type is supported")
		return
	}

	assertion := r.FormValue("assertion")
	if assertion == "" {
		httputil.WriteBadRequest(w, "invalid_request", "Missing assertion parameter")
		return
	}

	authClaims, err := s.idpService.ValidateAuthToken(assertion)
	if err != nil {
		httputil.WriteUnauthorized(w, "invalid_grant", fmt.Sprintf("Invalid assertion: %v", err))
		return
	}

	bearerToken, expiresIn, err := s.generateBearerToken(authClaims)
	if err != nil {
		httputil.WriteInternalError(w, "server_error", "Failed to generate bearer token")
		return
	}

	s.logTokenIssued(authClaims)

	httputil.WriteJSONNoCache(w, map[string]any{
		"access_token": bearerToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
}

func (s *Server) logTokenIssued(claims *models.AuthTokenClaims) {
	fmt.Printf("[TOKEN] Issued bearer token for user %s (BIG: %s, Role: %s)\n",
		claims.GivenName+" "+claims.FamilyName,
		claims.BIGNumber,
		claims.BIGRoleCode)
}

func (s *Server) generateBearerToken(authClaims *models.AuthTokenClaims) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(s.bearerTokenTTL)

	claims := jwt.MapClaims{
		"iss":         s.baseURL,
		"sub":         authClaims.Subject,
		"aud":         s.baseURL,
		"exp":         expiresAt.Unix(),
		"nbf":         now.Unix(),
		"iat":         now.Unix(),
		"jti":         uuid.New().String(),
		"big":         authClaims.BIGNumber,
		"role":        authClaims.BIGRoleCode,
		"ura":         authClaims.URA,
		"org":         authClaims.OrganizationName,
		"given_name":  authClaims.GivenName,
		"family_name": authClaims.FamilyName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.bearerTokenSecret))
	if err != nil {
		return "", 0, fmt.Errorf("signing token: %w", err)
	}

	s.mu.Lock()
	s.bearerTokens[tokenString] = &bearerTokenInfo{
		authClaims: authClaims,
		expiresAt:  expiresAt,
	}
	s.mu.Unlock()

	return tokenString, int64(s.bearerTokenTTL.Seconds()), nil
}

func (s *Server) validateBearerToken(tokenString string) (*models.AuthTokenClaims, error) {
	s.mu.RLock()
	info, exists := s.bearerTokens[tokenString]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	if time.Now().After(info.expiresAt) {
		s.mu.Lock()
		delete(s.bearerTokens, tokenString)
		s.mu.Unlock()
		return nil, fmt.Errorf("token expired")
	}

	return info.authClaims, nil
}

// HandleQIDORS handles QIDO-RS search requests.
func (s *Server) HandleQIDORS(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authorizeRequest(r, "ImagingStudy", "read")
	if err != nil {
		s.writeAuthError(w, err)
		return
	}

	patientID := r.URL.Query().Get("PatientID")

	s.mu.RLock()
	var results []*models.ImagingStudy
	for _, study := range s.studies {
		if patientID == "" || study.PatientID == patientID {
			results = append(results, study)
		}
	}
	s.mu.RUnlock()

	s.logAccess(claims, "searched studies for patient", patientID)

	w.Header().Set("Content-Type", dicomJSONContentType)
	json.NewEncoder(w).Encode(results)
}

// HandleWADORS handles WADO-RS retrieve requests.
func (s *Server) HandleWADORS(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authorizeRequest(r, "ImagingStudy", "read")
	if err != nil {
		s.writeAuthError(w, err)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/studies/")
	parts := strings.Split(path, "/")
	studyUID := parts[0]

	s.mu.RLock()
	study, exists := s.studies[studyUID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Study not found", http.StatusNotFound)
		return
	}

	s.logAccess(claims, "retrieved study", studyUID)

	if len(parts) > 1 && parts[1] == "metadata" {
		w.Header().Set("Content-Type", dicomJSONContentType)
		json.NewEncoder(w).Encode(study)
		return
	}

	w.Header().Set("Content-Type", "multipart/related; type=\"application/dicom\"")
	fmt.Fprintf(w, "[DICOM data for study %s - %d images]", studyUID, study.NumberOfImages)
}

func (s *Server) authorizeRequest(r *http.Request, resourceType, action string) (*models.AuthTokenClaims, error) {
	token, ok := httputil.ExtractBearerToken(r)
	if !ok {
		return nil, fmt.Errorf("missing bearer token")
	}

	claims, err := s.validateBearerToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}

func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	httputil.WriteUnauthorized(w, "unauthorized", err.Error())
}

func (s *Server) logAccess(claims *models.AuthTokenClaims, action, detail string) {
	fmt.Printf("[ACCESS] %s %s %s by %s %s (BIG: %s, %s)\n",
		action, detail,
		time.Now().Format(time.RFC3339),
		claims.GivenName, claims.FamilyName,
		claims.BIGNumber, claims.OrganizationName)
}
