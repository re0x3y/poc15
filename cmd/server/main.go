package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/reoxey/poc15/authz"
	"github.com/reoxey/poc15/dezi"
	"github.com/reoxey/poc15/dicomweb"
	"github.com/reoxey/poc15/idp"
	"github.com/reoxey/poc15/internal/config"
	"github.com/reoxey/poc15/internal/httputil"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	cfg        *config.AppConfig
)

func main() {
	flag.Parse()

	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Println("=== POC 15: Complete Integration Demo ===")
	fmt.Println("Starting HTTP servers for full flow demonstration")
	fmt.Println()

	// Initialize IDP service
	idpService, err := idp.NewService(&idp.Config{
		Issuer:         cfg.IDP.Issuer,
		AuthTokenTTL:   cfg.IDP.AuthTokenTTL,
		AccessTokenTTL: cfg.IDP.AccessTokenTTL,
	})
	if err != nil {
		log.Fatalf("Failed to initialize IDP: %v", err)
	}
	fmt.Printf("✓ IDP service initialized on %s\n", cfg.IDP.Issuer)

	// Initialize Authorization server
	authzServer := authz.NewServer(&authz.Config{
		Issuer:         cfg.Authz.Issuer,
		AuthCodeTTL:    cfg.Authz.AuthCodeTTL,
		AccessTokenTTL: cfg.Authz.AccessTokenTTL,
	})
	fmt.Printf("✓ Authorization server initialized on %s\n", cfg.Authz.Issuer)

	// Initialize DICOMweb (PACS) server
	dicomServer := dicomweb.NewServerWithConfig(
		cfg.DICOMweb.BaseURL,
		idpService,
		authzServer,
		&dicomweb.ServerConfig{
			BearerTokenTTL:    cfg.DICOMweb.BearerTokenTTL,
			BearerTokenSecret: cfg.DICOMweb.BearerTokenSecret,
			CleanupInterval:   cfg.DICOMweb.CleanupInterval,
		},
	)
	mux := http.NewServeMux()
	dicomServer.RegisterHandlers(mux)
	handler := httputil.LoggingMiddleware(mux, cfg.Logging.HTTPRequests)

	pacsServer := &http.Server{
		Addr:              cfg.Server.PACSAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
	}
	go func() {
		fmt.Printf("✓ DICOMweb (PACS) server started on http://localhost%s\n", cfg.Server.PACSAddr)
		if err := pacsServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("PACS server error: %v", err)
		}
	}()

	// Allow server to start
	time.Sleep(100 * time.Millisecond)

	fmt.Println("\n=== Starting Authentication Flow ===")
	fmt.Println()

	// Step 1: Initialize DEZI client
	fmt.Println("\n1. Initializing DEZI client...")
	fmt.Printf("   Using issuer: %s\n", cfg.Dezi.Issuer)
	fmt.Printf("   Using client_id: %s\n", cfg.Dezi.ClientID)
	if cfg.Dezi.ClientSecret != "" {
		fmt.Printf("   Using client_secret: %s....\n", cfg.Dezi.ClientSecret[:1])
	}

	deziClient, err := dezi.NewClientWithConfig(&dezi.Config{
		Issuer:       cfg.Dezi.Issuer,
		ClientID:     cfg.Dezi.ClientID,
		ClientSecret: cfg.Dezi.ClientSecret,
		RedirectURI:  cfg.Dezi.RedirectURI,
		Scopes:       cfg.Dezi.Scopes,
	}, &dezi.ClientOptions{
		HTTPTimeout:           cfg.Dezi.HTTPTimeout,
		TokenExchangeResource: cfg.Dezi.TokenExchangeResource,
		IntrospectURL:         cfg.Dezi.IntrospectURL,
		LogHTTPRequests:       cfg.Logging.HTTPRequests,
		IHEIUA:                cfg.IHEIUA,
	})
	if err != nil {
		log.Fatalf("Failed to create DEZI client: %v", err)
	}
	fmt.Println("   ✓ DEZI client initialized")

	// Step 2: Generate PKCE parameters
	fmt.Println("\n2. Generating PKCE parameters...")
	pkce, err := dezi.GeneratePKCE()
	if err != nil {
		log.Fatalf("Failed to generate PKCE: %v", err)
	}
	fmt.Printf("   ✓ Code verifier generated (length: %d)\n", len(pkce.CodeVerifier))
	fmt.Println("   ✓ Code challenge generated (method: S256)")

	// Step 3: Generate authorization URL
	fmt.Println("\n3. Authorization URL generated...")
	fmt.Println("   (In production, user would be redirected here)")

	state := fmt.Sprintf("state-%d", time.Now().UnixNano())
	authURL, err := deziClient.GetAuthorizationURL(state, pkce)
	if err != nil {
		log.Fatalf("Failed to get authorization URL: %v", err)
	}

	// Step 4: Wait for authorization code from DEZI
	fmt.Println("\n4. Waiting for authorization code from DEZI...")
	fmt.Println("   Please complete the following steps:")
	fmt.Println("   1. Open this URL in your browser:")
	fmt.Printf("      %s\n", authURL)
	fmt.Println("   2. Log in and authorize the application")
	fmt.Println("   3. After redirect, copy the 'code' parameter from the callback URL")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("   Enter the authorization code: ")
	authCode, _ := reader.ReadString('\n')
	authCode = strings.TrimSpace(authCode)
	fmt.Println("   ✓ Authorization code received")

	// Step 5.1: Exchange authorization code for token
	fmt.Println("\n5.1. Exchanging authorization code for token...")
	tokenResp, err := deziClient.ExchangeCode(authCode, pkce.CodeVerifier)
	if err != nil {
		log.Fatalf("Failed to exchange code: %v", err)
	}
	fmt.Printf("   ✓ Code exchanged (expires in %d seconds)\n", tokenResp.ExpiresIn)

	// Step 5.2: Exchange token for access token (token exchange)
	fmt.Println("\n5.2. Exchanging token for access token...")
	accessTokenResp, err := deziClient.ExchangeToken(tokenResp.AccessToken)
	if err != nil {
		log.Fatalf("Failed to exchange token: %v", err)
	}
	fmt.Printf("   ✓ Access token received (expires in %d seconds)\n", accessTokenResp.ExpiresIn)

	// Step 6: Validate access token with JWKS
	fmt.Println("\n6. Validating access token with JWKS...")
	claims, err := deziClient.ValidateToken(accessTokenResp.AccessToken)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}
	fmt.Println("   ✓ Access token validated")

	// Step 8: Register access token with IDP
	fmt.Println("\n8. Registering access token with IDP...")
	idpService.StoreAccessToken(accessTokenResp.AccessToken, claims)
	fmt.Println("   ✓ Access token stored for token exchange")

	// Step 9: Request auth-token for PACS access
	fmt.Println("\n9. Requesting auth-token for PACS access...")
	authToken, err := idpService.ExchangeToken(accessTokenResp.AccessToken, cfg.DICOMweb.BaseURL)
	if err != nil {
		log.Fatalf("Failed to get auth-token: %v", err)
	}
	fmt.Printf("   ✓ Auth-token generated for: %s\n", cfg.DICOMweb.BaseURL)
	fmt.Printf("   ✓ Token length: %d characters\n", len(authToken))

	// Step 10: Validate auth-token
	fmt.Println("\n10. Validating auth-token...")
	validatedClaims, err := idpService.ValidateAuthToken(authToken)
	if err != nil {
		log.Fatalf("Failed to validate auth-token: %v", err)
	}
	fmt.Println("   ✓ Auth-token signature verified")
	fmt.Printf("   ✓ Subject: %s\n", validatedClaims.RegisteredClaims.Subject)
	fmt.Printf("   ✓ Issuer: %s\n", validatedClaims.RegisteredClaims.Issuer)
	expiresAt := validatedClaims.RegisteredClaims.ExpiresAt
	if expiresAt != nil {
		fmt.Printf("   ✓ Expires: %s\n", expiresAt.Time.Format(time.RFC3339))
	}

	patientID := "patient-001"

	// Step 11: Create DICOMweb client and search for studies
	fmt.Println("\n11. Searching for imaging studies via DICOMweb...")
	fmt.Println("   (Client will automatically exchange tokens with DICOMweb server)")
	pacsClient := dicomweb.NewClient(cfg.DICOMweb.BaseURL, func(resource string) (string, error) {
		return idpService.ExchangeToken(accessTokenResp.AccessToken, resource)
	})

	studies, err := pacsClient.SearchStudies(patientID)
	if err != nil {
		log.Fatalf("Failed to search studies: %v", err)
	}
	fmt.Printf("   ✓ Found %d studies for %s:\n", len(studies), patientID)
	for i, study := range studies {
		fmt.Printf("     %d. %s - %s (%s)\n", i+1, study.StudyDate.Format("2006-01-02"),
			study.StudyDescription, study.Modality)
		fmt.Printf("        Study UID: %s\n", study.StudyInstanceUID)
		fmt.Printf("        Images: %d in %d series\n", study.NumberOfImages, study.NumberOfSeries)
	}

	// Step 12: Retrieve metadata for first study
	if len(studies) > 0 {
		fmt.Printf("\n12. Retrieving metadata for study: %s...\n", studies[0].StudyDescription)
		metadata, err := pacsClient.RetrieveMetadata(studies[0].StudyInstanceUID)
		if err != nil {
			log.Printf("   Warning: Failed to retrieve metadata: %v", err)
		} else {
			fmt.Println("   ✓ Metadata retrieved successfully")
			fmt.Printf("   ✓ Accession number: %s\n", metadata.AccessionNumber)
		}
	}

	// Step 13: Perform authorization check (ITI-102)
	fmt.Println("\n13. Performing authorization check (ITI-102)...")
	decision, err := authzServer.PerformAuthorizationDecision(authToken, "Patient/"+patientID, "read")
	if err != nil {
		log.Printf("   Warning: Authorization check failed: %v", err)
	} else {
		fmt.Printf("   ✓ Authorization decision: %s\n", decision.Decision)
		if expiresAt != nil {
			fmt.Printf("   ✓ Access granted until: %s\n", expiresAt.Time.Format(time.RFC3339))
		}
	}

	fmt.Println("\n=== Authentication Flow Completed Successfully ===")

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("Servers are running. Press Ctrl+C to stop.")
	fmt.Println("\nEndpoints:")
	fmt.Printf("  PACS Token: http://localhost%s/token\n", cfg.Server.PACSAddr)
	fmt.Printf("  PACS QIDO:  http://localhost%s/studies?PatientID=%s\n", cfg.Server.PACSAddr, patientID)

	// Keep servers running
	select {}
}
