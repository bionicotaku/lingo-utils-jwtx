package jwtx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/api/idtoken"
)

func TestValidator_JWKSSuccess(t *testing.T) {
	privateKey, jwksURL, kid := newJWKS(t)

	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{
			{
				Name:        "google",
				JWKSURL:     jwksURL,
				Issuer:      "https://sts.googleapis.com",
				Audience:    "https://template.local.dev",
				ClockSkew:   10 * time.Second,
				MinRefresh:  time.Second,
				HTTPTimeout: time.Second,
			},
		},
	}

	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	ctx := context.Background()
	if err := validator.Warmup(ctx, "google"); err != nil {
		t.Fatalf("Warmup: %v", err)
	}

	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Issuer("https://sts.googleapis.com").
		Subject("serviceaccount:svc-template@project.iam.gserviceaccount.com").
		Audience([]string{"https://template.local.dev"}).
		IssuedAt(now).
		NotBefore(now.Add(-time.Minute)).
		Expiration(now.Add(time.Hour)).
		JwtID("token-1").
		Claim("email", "svc-template@project.iam.gserviceaccount.com").
		Claim("role", "system").
		Claim("session_id", "session-123")

	token := sign(t, builder, privateKey, kid)

	claims, err := validator.Validate(ctx, token, "google")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if claims.Subject != "serviceaccount:svc-template@project.iam.gserviceaccount.com" {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}
	if claims.Email != "svc-template@project.iam.gserviceaccount.com" {
		t.Fatalf("unexpected email: %s", claims.Email)
	}
	if claims.Role != "system" {
		t.Fatalf("unexpected role: %s", claims.Role)
	}
	if claims.SessionID != "session-123" {
		t.Fatalf("unexpected session id: %s", claims.SessionID)
	}
    if len(claims.Audience) != 1 || claims.Audience[0] != "https://template.local.dev" {
        t.Fatalf("unexpected audience: %v", claims.Audience)
    }
}

func TestValidator_SubjectNotAllowed(t *testing.T) {
	privateKey, jwksURL, kid := newJWKS(t)

	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{
			{
				Name:        "supabase",
				JWKSURL:     jwksURL,
				Issuer:      "https://supabase-project.supabase.co/auth/v1",
				Audience:    "authenticated",
				ClockSkew:   time.Minute,
				MinRefresh:  time.Minute,
				HTTPTimeout: time.Second,
				// No allowed subjects -> all accepted
			},
		},
	}

	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	token := sign(t, jwt.NewBuilder().
		Issuer("https://supabase-project.supabase.co/auth/v1").
		Subject("user-1").
		Audience([]string{"authenticated"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute)).
		Claim("email", "user@example.com"),
		privateKey,
		kid,
	)

	if _, err := validator.Validate(context.Background(), token, "supabase"); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Update config with allowed subjects and recreate validator.
	cfg.Issuers[0].AllowedSubjects = []string{"user-allowed"}
	validator, err = NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), token, "supabase")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var jwtxErr *Error
	if !errors.As(err, &jwtxErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if jwtxErr.Code != ErrCodeSubjectNotAllowed {
		t.Fatalf("unexpected error code: %s", jwtxErr.Code)
	}
}

func TestValidator_InvalidIssuer(t *testing.T) {
	privateKey, jwksURL, kid := newJWKS(t)

	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{
			{
				Name:        "google",
				JWKSURL:     jwksURL,
				Issuer:      "https://sts.googleapis.com",
				Audience:    "https://template.local.dev",
				ClockSkew:   time.Second,
				MinRefresh:  time.Second,
				HTTPTimeout: time.Second,
			},
		},
	}
	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	token := sign(t, jwt.NewBuilder().
		Issuer("https://other-issuer").
		Subject("serviceaccount:svc-template@project.iam.gserviceaccount.com").
		Audience([]string{"https://template.local.dev"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute)),
		privateKey,
		kid,
	)

	_, err = validator.Validate(context.Background(), token, "google")
	if err == nil {
		t.Fatalf("expected error")
	}
	var jwtxErr *Error
	if !errors.As(err, &jwtxErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if jwtxErr.Code != ErrCodeInvalidIssuer {
		t.Fatalf("expected invalid issuer, got %s", jwtxErr.Code)
	}
}

func TestValidator_UnknownIssuer(t *testing.T) {
	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{
			{
				Name:     "known",
				JWKSURL:  "https://example.com/jwks",
				Issuer:   "issuer",
				Audience: "aud",
			},
		},
	}
	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), "token", "missing")
	if err == nil {
		t.Fatalf("expected error")
	}
	var jwtxErr *Error
	if !errors.As(err, &jwtxErr) || jwtxErr.Code != ErrCodeIssuerNotRegistered {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidator_JWKSExpiredAndNotYetValid(t *testing.T) {
	privateKey, jwksURL, kid := newJWKS(t)
	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{{
			Name:        "supabase",
			JWKSURL:     jwksURL,
			Issuer:      "https://supabase.example/auth/v1",
			Audience:    "authenticated",
			ClockSkew:   time.Second,
			MinRefresh:  time.Second,
			HTTPTimeout: time.Second,
		}},
	}
	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	makeToken := func(builder *jwt.Builder) string {
		return sign(t, builder, privateKey, kid)
	}

	t.Run("expired token", func(t *testing.T) {
		now := time.Now()
		token := makeToken(jwt.NewBuilder().
			Issuer("https://supabase.example/auth/v1").
			Subject("user-1").
			Audience([]string{"authenticated"}).
			IssuedAt(now.Add(-2 * time.Hour)).
			Expiration(now.Add(-time.Minute)))

		_, err := validator.Validate(context.Background(), token, "supabase")
		if err == nil {
			t.Fatalf("expected error")
		}
		t.Logf("expired error: %v", err)
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("expected *Error, got %T", err)
		}
		if e.Code != ErrCodeExpired {
			t.Fatalf("expected ErrCodeExpired, got %s", e.Code)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		now := time.Now()
		token := makeToken(jwt.NewBuilder().
			Issuer("https://supabase.example/auth/v1").
			Subject("user-1").
			Audience([]string{"authenticated"}).
			IssuedAt(now).
			NotBefore(now.Add(time.Hour)).
			Expiration(now.Add(2 * time.Hour)))

		_, err := validator.Validate(context.Background(), token, "supabase")
		if err == nil {
			t.Fatalf("expected error")
		}
		t.Logf("not yet valid error: %v", err)
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("expected *Error, got %T", err)
		}
		if e.Code != ErrCodeNotYetValid {
			t.Fatalf("expected ErrCodeNotYetValid, got %s", e.Code)
		}
	})
}

func TestValidator_GoogleValidationHonorsTimeout(t *testing.T) {
	t.Helper()

	original := googleValidate
	defer func() { googleValidate = original }()

	var (
		observedDeadline time.Time
		validateCalls    int
	)

	googleValidate = func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
		validateCalls++
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected validation context to have deadline")
		}
		observedDeadline = dl
		return &idtoken.Payload{
			Issuer:   "https://accounts.google.com",
			Audience: audience,
			Subject:  "serviceaccount:svc@example.com",
			IssuedAt: time.Now().Add(-time.Minute).Unix(),
			Expires:  time.Now().Add(time.Hour).Unix(),
			Claims: map[string]any{
				"email": "svc@example.com",
			},
		}, nil
	}

	timeout := 150 * time.Millisecond
	cfg := ValidatorConfig{
		Issuers: []IssuerConfig{
			{
				Name:        "google",
				Audience:    "https://api.local.dev",
				Issuer:      "https://accounts.google.com",
				HTTPTimeout: timeout,
			},
		},
	}

	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	start := time.Now()
	claims, err := validator.Validate(context.Background(), "dummy-token", "google")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "serviceaccount:svc@example.com" {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}
	if validateCalls != 1 {
		t.Fatalf("expected googleValidate invoked once, got %d", validateCalls)
	}
	if observedDeadline.IsZero() {
		t.Fatal("expected observed deadline to be recorded")
	}

	elapsed := observedDeadline.Sub(start)
	if elapsed < timeout/2 || elapsed > timeout*2 {
		t.Fatalf("deadline outside expected bounds: want approx %v, got %v", timeout, elapsed)
	}
}

func newJWKS(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	const kid = "test-key"
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}

	payload, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	return key, server.URL, kid
}

func sign(t *testing.T, builder *jwt.Builder, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	token, err := builder.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	jwkPriv, err := jwk.FromRaw(key)
	if err != nil {
		t.Fatalf("private key jwk: %v", err)
	}
	if err := jwkPriv.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	if kid != "" {
		if err := jwkPriv.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatalf("set kid: %v", err)
		}
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, jwkPriv))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}
