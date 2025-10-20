package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

    "github.com/bionicotaku/lingo-utils-jwtx"
)

func main() {
	envPath := defaultEnvPath()
	if err := loadEnvFile(envPath); err != nil {
		log.Printf("warning: load %s: %v", envPath, err)
	}

	var (
		defaultJWKSURL     = os.Getenv("GOOGLE_JWKS_URL")
		defaultIssuer      = os.Getenv("GOOGLE_ISSUER")
		defaultAudience    = os.Getenv("GOOGLE_AUDIENCE")
		defaultServiceAcct = os.Getenv("GOOGLE_SERVICE_ACCOUNT")
		defaultToken       = os.Getenv("GOOGLE_ID_TOKEN")
	)

	jwksURL := flag.String("jwks-url", defaultJWKSURL, "Google JWKS URL (env GOOGLE_JWKS_URL)")
	issuer := flag.String("issuer", defaultIssuer, "Expected issuer (env GOOGLE_ISSUER)")
	audience := flag.String("audience", defaultAudience, "Expected audience (env GOOGLE_AUDIENCE)")
	serviceAccount := flag.String("service-account", defaultServiceAcct, "Service account to impersonate (env GOOGLE_SERVICE_ACCOUNT)")
	token := flag.String("token", defaultToken, "Existing ID token; if empty CLI will use jwtx.Provider (env GOOGLE_ID_TOKEN)")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout for token fetch")
	envFlag := flag.String("env", envPath, "Path to .env file")
	flag.Parse()

	if *envFlag != "" && *envFlag != envPath {
		if err := loadEnvFile(*envFlag); err != nil {
			log.Printf("warning: load %s: %v", *envFlag, err)
		}
		reloadDefaults(jwksURL, issuer, audience, serviceAccount, token)
	}

	if *audience == "" {
		flag.Usage()
		log.Fatal("audience is required (via flag, .env, or environment variables)")
	}
	if *token == "" {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		provider := jwtx.NewProvider(jwtx.ProviderConfig{
			ServiceAccount: *serviceAccount,
		})
		tok, err := provider.Token(ctx, *audience)
		if err != nil {
			log.Fatalf("failed to obtain identity token via provider: %v (ensure ADC或GOOGLE_APPLICATION_CREDENTIALS有效，并拥有 roles/iam.serviceAccountTokenCreator 权限)", err)
		}
		*token = tok
		log.Println("acquired Google identity token via provider")
	}

	cfg := jwtx.ValidatorConfig{
		Issuers: []jwtx.IssuerConfig{
			{
				Name:        "google",
				JWKSURL:     *jwksURL,
				Issuer:      *issuer,
				Audience:    *audience,
				HTTPTimeout: 5 * time.Second,
				ClockSkew:   30 * time.Second,
				MinRefresh:  time.Minute,
			},
		},
	}

	validator, err := jwtx.NewValidator(cfg)
	if err != nil {
		log.Fatalf("create validator: %v", err)
	}

	claims, err := validator.Validate(context.Background(), *token, "google")
	if err != nil {
		log.Fatalf("validation failed: %v", err)
	}

	printClaims(claims)
}

// no helper needed; provider handles token minting.

func printClaims(claims *jwtx.Claims) {
	fmt.Println("== Google Identity Token Verified ==")
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
	if len(claims.CustomClaims) > 0 {
		fmt.Println("custom_claims:")
		for k, v := range claims.CustomClaims {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

func defaultEnvPath() string {
	if path := os.Getenv("JWXT_ENV_FILE"); path != "" {
		return path
	}
	return ".env"
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
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			log.Printf("warning: set env %s: %v", key, err)
		}
	}
	return scanner.Err()
}

func reloadDefaults(jwksURL, issuer, audience, serviceAccount, token *string) {
	if jwksURL != nil && *jwksURL == "" {
		*jwksURL = os.Getenv("GOOGLE_JWKS_URL")
	}
	if issuer != nil && *issuer == "" {
		*issuer = os.Getenv("GOOGLE_ISSUER")
	}
	if audience != nil && *audience == "" {
		*audience = os.Getenv("GOOGLE_AUDIENCE")
	}
	if serviceAccount != nil && *serviceAccount == "" {
		*serviceAccount = os.Getenv("GOOGLE_SERVICE_ACCOUNT")
	}
	if token != nil && *token == "" {
		*token = os.Getenv("GOOGLE_ID_TOKEN")
	}
}
