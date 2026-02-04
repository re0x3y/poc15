// Package models contains data structures and JWT claims for POC 15.
package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig represents OpenID Connect discovery metadata.
type OIDCConfig struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSUri                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

// TokenResponse represents an OAuth 2.0 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// DeziClaims represents the DEZI declaration claims.
type DeziClaims struct {
	jwt.RegisteredClaims
	// Standard claims for compatibility
	Subject   string   `json:"-"`
	Issuer    string   `json:"-"`
	Audience  []string `json:"-"`
	ExpiresAt int64    `json:"-"`
	// DEZI-specific claims
	BIGNumber        string `json:"big_number,omitempty"`
	BIGRoleCode      string `json:"big_role_code,omitempty"`
	URA              string `json:"ura,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	GivenName        string `json:"given_name,omitempty"`
	FamilyName       string `json:"family_name,omitempty"`
	Email            string `json:"email,omitempty"`
	AuthTime         int64  `json:"auth_time,omitempty"`
}

// AuthTokenClaims represents claims in an auth-token (IDP → Source).
type AuthTokenClaims struct {
	jwt.RegisteredClaims
	BIGNumber        string `json:"big_number"`
	BIGRoleCode      string `json:"big_role_code"`
	URA              string `json:"ura"`
	OrganizationName string `json:"organization_name"`
	GivenName        string `json:"given_name"`
	FamilyName       string `json:"family_name"`
	AuthTime         int64  `json:"auth_time"`
	TargetResource   string `json:"target_resource"`
}

// AccessTokenClaims represents claims in an IHE IUA access token.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	TID        string `json:"tid,omitempty"`
	Extensions struct {
		IHEIUA IHEIUAExtension `json:"ihe_iua,omitempty"`
	} `json:"extensions,omitempty"`
}

// IHEIUAExtension represents IHE IUA specific claims.
type IHEIUAExtension struct {
	SubjectName           string         `json:"subject_name,omitempty"`
	SubjectOrganization   string         `json:"subject_organization,omitempty"`
	SubjectOrganizationID string         `json:"subject_organization_id,omitempty"`
	PersonID              string         `json:"person_id,omitempty"`
	BIGRoleCode           string         `json:"big_role_code,omitempty"`
	PurposeOfUse          []PurposeOfUse `json:"purpose_of_use,omitempty"`
}

// PurposeOfUse represents the purpose of use coding.
type PurposeOfUse struct {
	System string `json:"system"`
	Code   string `json:"code"`
}

// ImagingStudy represents a DICOM imaging study.
type ImagingStudy struct {
	StudyInstanceUID string    `json:"studyInstanceUID"`
	PatientID        string    `json:"patientID"`
	StudyDate        time.Time `json:"studyDate"`
	StudyDescription string    `json:"studyDescription"`
	Modality         string    `json:"modality"`
	AccessionNumber  string    `json:"accessionNumber"`
	NumberOfSeries   int       `json:"numberOfSeries"`
	NumberOfImages   int       `json:"numberOfImages"`
}

// AuthorizationDecision represents an authorization decision (ITI-102).
type AuthorizationDecision struct {
	Decision    string   `json:"decision"`
	Resource    string   `json:"resource"`
	Action      string   `json:"action"`
	Subject     string   `json:"subject"`
	Obligations []string `json:"obligations,omitempty"`
}
