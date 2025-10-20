package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bionicotaku/lingo-utils-jwtx"
	"golang.org/x/oauth2"
)

func main() {
	envPath := defaultEnvPath()
	if err := loadEnvFile(envPath); err != nil {
		log.Printf("warning: load %s: %v", envPath, err)
	}

	var (
		defaultJWKS       = os.Getenv("SUPABASE_JWKS_URL")
		defaultIssuer     = os.Getenv("SUPABASE_ISSUER")
		defaultAudience   = os.Getenv("SUPABASE_AUDIENCE")
		defaultProjectURL = os.Getenv("SUPABASE_PROJECT_URL")
		defaultAPIKey     = os.Getenv("SUPABASE_API_KEY")
		defaultEmail      = os.Getenv("SUPABASE_EMAIL")
		defaultPassword   = os.Getenv("SUPABASE_PASSWORD")
		defaultToken      = os.Getenv("SUPABASE_JWT")
	)

	jwksURL := flag.String("jwks-url", defaultJWKS, "Supabase JWKS URL (env SUPABASE_JWKS_URL)")
	issuer := flag.String("issuer", defaultIssuer, "Expected issuer (env SUPABASE_ISSUER)")
	audience := flag.String("audience", defaultAudience, "Expected audience (env SUPABASE_AUDIENCE)")
	projectURL := flag.String("project-url", defaultProjectURL, "Supabase project base URL (env SUPABASE_PROJECT_URL)")
	apiKey := flag.String("apikey", defaultAPIKey, "Supabase anon/service role API key (env SUPABASE_API_KEY)")
	email := flag.String("email", defaultEmail, "Supabase user email (env SUPABASE_EMAIL)")
	password := flag.String("password", defaultPassword, "Supabase user password (env SUPABASE_PASSWORD)")
	token := flag.String("token", defaultToken, "JWT to validate (env SUPABASE_JWT)")
	timeout := flag.Duration("timeout", 5*time.Second, "HTTP timeout for JWKS fetch")
	envFileFlag := flag.String("env", envPath, "Optional path to .env file (default .env)")
	flag.Parse()

	if *envFileFlag != "" && *envFileFlag != envPath {
		if err := loadEnvFile(*envFileFlag); err != nil {
			log.Printf("warning: load %s: %v", *envFileFlag, err)
		}
		reloadDefaults(jwksURL, issuer, audience, projectURL, apiKey, email, password, token)
	}

	if *jwksURL == "" || *issuer == "" || *audience == "" {
		flag.Usage()
		log.Fatal("jwks-url, issuer, and audience are required")
	}

	if *token == "" {
		if *apiKey == "" || *email == "" || *password == "" {
			flag.Usage()
			log.Fatal("email, password, and api key required to mint Supabase token via provider")
		}
		projectURL := *projectURL
		if projectURL == "" {
			projectURL = deriveProjectURL(*jwksURL)
		}
		if projectURL == "" {
			log.Fatal("project-url is required when fetching a token; set flag/env SUPABASE_PROJECT_URL")
		}

		factory := func(ctx context.Context, _ string, _ jwtx.ProviderParams) (oauth2.TokenSource, error) {
			tok, err := fetchAccessToken(ctx, projectURL, *apiKey, *email, *password, *timeout)
			if err != nil {
				return nil, err
			}
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok, Expiry: time.Now().Add(time.Hour)}), nil
		}
		supabaseProvider := jwtx.NewProvider(jwtx.ProviderConfig{TokenFactory: factory})
		tok, err := supabaseProvider.Token(context.Background(), *audience)
		if err != nil {
			log.Fatalf("failed to fetch access token via provider: %v", err)
		}
		*token = tok
		log.Println("acquired fresh Supabase access token via provider")
	}

	cfg := jwtx.ValidatorConfig{
		Issuers: []jwtx.IssuerConfig{
			{
				Name:        "supabase",
				JWKSURL:     *jwksURL,
				Issuer:      *issuer,
				Audience:    *audience,
				HTTPTimeout: *timeout,
				ClockSkew:   30 * time.Second,
				MinRefresh:  time.Minute,
			},
		},
	}

	validator, err := jwtx.NewValidator(cfg)
	if err != nil {
		log.Fatalf("create validator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := validator.Warmup(ctx, "supabase"); err != nil {
		log.Printf("warmup warning: %v", err)
	}

	claims, err := validator.Validate(context.Background(), *token, "supabase")
	if err != nil {
		log.Fatalf("validation failed: %v", err)
	}

	printClaims(claims)
}

func defaultEnvPath() string {
	if path := os.Getenv("JWXT_ENV_FILE"); path != "" {
		return path
	}
	return ".env"
}

func reloadDefaults(jwksURL, issuer, audience, projectURL, apiKey, email, password, token *string) {
	if jwksURL != nil && *jwksURL == "" {
		*jwksURL = os.Getenv("SUPABASE_JWKS_URL")
	}
	if issuer != nil && *issuer == "" {
		*issuer = os.Getenv("SUPABASE_ISSUER")
	}
	if audience != nil && *audience == "" {
		*audience = os.Getenv("SUPABASE_AUDIENCE")
	}
	if projectURL != nil && *projectURL == "" {
		*projectURL = os.Getenv("SUPABASE_PROJECT_URL")
	}
	if apiKey != nil && *apiKey == "" {
		*apiKey = os.Getenv("SUPABASE_API_KEY")
	}
	if email != nil && *email == "" {
		*email = os.Getenv("SUPABASE_EMAIL")
	}
	if password != nil && *password == "" {
		*password = os.Getenv("SUPABASE_PASSWORD")
	}
	if token != nil && *token == "" {
		*token = os.Getenv("SUPABASE_JWT")
	}
}

func printClaims(claims *jwtx.Claims) {
	fmt.Println("== Supabase JWT Verified ==")
	fmt.Printf("subject      : %s\n", claims.Subject)
	fmt.Printf("email        : %s\n", claims.Email)
	fmt.Printf("issuer       : %s\n", claims.Issuer)
	fmt.Printf("audience     : %s\n", claims.Audience)
	if !claims.ExpiresAt.IsZero() {
		fmt.Printf("expires_at   : %s\n", claims.ExpiresAt.Format(time.RFC3339))
	}
	if !claims.NotBefore.IsZero() {
		fmt.Printf("not_before   : %s\n", claims.NotBefore.Format(time.RFC3339))
	}
	if claims.SessionID != "" {
		fmt.Printf("session_id   : %s\n", claims.SessionID)
	}
	if len(claims.CustomClaims) > 0 {
		fmt.Println("custom_claims:")
		for k, v := range claims.CustomClaims {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

func loadEnvFile(path string) error {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("warning: invalid line %d in %s", lineNum, filepath.Base(path))
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if key == "" {
			continue
		}
		if _, present := os.LookupEnv(key); present {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			log.Printf("warning: set env %s: %v", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

type passwordGrantResponse struct {
	AccessToken string `json:"access_token"`
}

func fetchAccessToken(ctx context.Context, projectURL, apiKey, email, password string, timeout time.Duration) (string, error) {
	if projectURL == "" {
		return "", errors.New("project URL required to fetch token")
	}
	base := strings.TrimRight(projectURL, "/")
	endpoint := base + "/auth/v1/token?grant_type=password"

	body := map[string]string{
		"email":    email,
		"password": password,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("apikey", apiKey)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("supabase auth returned %s", resp.Status)
	}
	var pg passwordGrantResponse
	if err := json.NewDecoder(resp.Body).Decode(&pg); err != nil {
		return "", err
	}
	if pg.AccessToken == "" {
		return "", errors.New("response did not include access_token")
	}
	return pg.AccessToken, nil
}

func deriveProjectURL(jwks string) string {
	if jwks == "" {
		return ""
	}
	u, err := url.Parse(jwks)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
