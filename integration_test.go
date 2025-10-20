package jwtx

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSupabaseIntegration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("RUN_INTEGRATION_TESTS not set to true")
	}

	supabaseURL := strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	if supabaseURL == "" {
		t.Fatal("SUPABASE_URL environment variable required")
	}

	jwksURL := strings.TrimRight(supabaseURL, "/") + "/auth/v1/.well-known/jwks.json"
	issuer := strings.TrimRight(supabaseURL, "/") + "/auth/v1"

	resp, err := http.Get(jwksURL)
	if err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("JWKS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("JWKS has no keys: %v", jwks)
	}

	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{{
			Name:        "supabase",
			JWKSURL:     jwksURL,
			Issuer:      issuer,
			Audience:    "authenticated",
			ClockSkew:   time.Minute,
			MinRefresh:  time.Minute,
			HTTPTimeout: 5 * time.Second,
		}},
	}

	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	if token := strings.TrimSpace(os.Getenv("SUPABASE_TEST_TOKEN")); token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		claims, err := validator.Validate(ctx, token, "supabase")
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if claims.Subject == "" {
			t.Fatal("claims.Subject empty")
		}
	}
}
