package jwtx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/api/idtoken"
)

var googleValidate = idtoken.Validate

// Validator validates JWT tokens issued by configured issuers.
type Validator struct {
	mu            sync.RWMutex
	issuers       map[string]*issuerState
	defaultIssuer string
}

type issuerState struct {
	cfg             IssuerConfig
	cache           *jwk.Cache
	allowedSubjects map[string]struct{}
	google          bool
}

// NewValidator builds a validator from the given configuration.
func NewValidator(cfg ValidatorConfig) (*Validator, error) {
	index, err := cfg.issuerIndex()
	if err != nil {
		return nil, err
	}

	defaultIssuer := ""
	if len(cfg.Issuers) == 1 {
		defaultIssuer = cfg.Issuers[0].Name
	}

	v := &Validator{
		issuers:       make(map[string]*issuerState, len(index)),
		defaultIssuer: defaultIssuer,
	}
	for name, issuerCfg := range index {
		state := &issuerState{
			cfg:             issuerCfg,
			allowedSubjects: toSet(issuerCfg.AllowedSubjects),
			google:          issuerCfg.JWKSURL == "",
		}
		if !state.google {
			cache := jwk.NewCache(context.Background())
			httpClient := &http.Client{
				Timeout: issuerCfg.HTTPTimeout,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
				},
			}
			if err := cache.Register(
				issuerCfg.JWKSURL,
				jwk.WithMinRefreshInterval(issuerCfg.MinRefresh),
				jwk.WithHTTPClient(httpClient),
			); err != nil {
				return nil, fmt.Errorf("register jwks for %q: %w", name, err)
			}
			state.cache = cache
		}
		v.issuers[name] = state
	}

	return v, nil
}

// Warmup refreshes JWKS for the specified issuer.
func (v *Validator) Warmup(ctx context.Context, issuerName string) error {
	state, ok := v.lookupIssuer(issuerName)
	if !ok {
		return newError(ErrCodeIssuerNotRegistered, fmt.Errorf("issuer %q not found", issuerName))
	}
	if state.google {
		return nil
	}
	refreshCtx := ctx
	if state.cfg.HTTPTimeout > 0 {
		var cancel context.CancelFunc
		refreshCtx, cancel = context.WithTimeout(ctx, state.cfg.HTTPTimeout)
		defer cancel()
	}
	if _, err := state.cache.Refresh(refreshCtx, state.cfg.JWKSURL); err != nil {
		return newError(ErrCodeJWKSUnavailable, err)
	}
	return nil
}

// Validate verifies the token using the issuer identified by issuerName.
func (v *Validator) Validate(ctx context.Context, token, issuerName string) (*Claims, error) {
	if issuerName == "" {
		issuerName = v.defaultIssuer
	}
	if issuerName == "" {
		return nil, newError(ErrCodeIssuerNotRegistered, fmt.Errorf("issuer not specified"))
	}

	if token == "" {
		return nil, newError(ErrCodeInvalidToken, errors.New("token is empty"))
	}
	state, ok := v.lookupIssuer(issuerName)
	if !ok {
		return nil, newError(ErrCodeIssuerNotRegistered, fmt.Errorf("issuer %q not found", issuerName))
	}
	if state.google {
		return v.validateGoogle(ctx, token, state)
	}
	return v.validateJWKS(ctx, token, state)
}

func (v *Validator) validateJWKS(ctx context.Context, token string, state *issuerState) (*Claims, error) {
	keySet, err := state.cache.Get(ctx, state.cfg.JWKSURL)
	if err != nil {
		return nil, newError(ErrCodeJWKSUnavailable, err)
	}

	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet))
	if err != nil {
		if mapped := classifyJWKSValidationError(err); mapped != nil {
			return nil, mapped
		}
		return nil, newError(ErrCodeInvalidToken, err)
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithAcceptableSkew(state.cfg.ClockSkew),
		jwt.WithIssuer(state.cfg.Issuer),
	}
	if state.cfg.Audience != "" {
		validateOpts = append(validateOpts, jwt.WithAudience(state.cfg.Audience))
	}
	if err := jwt.Validate(parsed, validateOpts...); err != nil {
		switch {
		case errors.Is(err, jwt.ErrInvalidIssuer()):
			return nil, newError(ErrCodeInvalidIssuer, err)
		case errors.Is(err, jwt.ErrInvalidAudience()):
			return nil, newError(ErrCodeInvalidAudience, err)
		case errors.Is(err, jwt.ErrTokenExpired()):
			return nil, newError(ErrCodeExpired, err)
		case errors.Is(err, jwt.ErrTokenNotYetValid()):
			return nil, newError(ErrCodeNotYetValid, err)
		default:
			if mapped := classifyJWKSValidationError(err); mapped != nil {
				return nil, mapped
			}
			return nil, newError(ErrCodeInvalidToken, err)
		}
	}

	claims := extractJWKSClaims(parsed)
	if !state.subjectAllowed(claims) {
		return nil, newError(ErrCodeSubjectNotAllowed, fmt.Errorf("subject %q not allowed", claims.Subject))
	}

	return claims, nil
}

func (v *Validator) validateGoogle(ctx context.Context, token string, state *issuerState) (*Claims, error) {
	validateCtx := ctx
	if state.cfg.HTTPTimeout > 0 {
		var cancel context.CancelFunc
		validateCtx, cancel = context.WithTimeout(ctx, state.cfg.HTTPTimeout)
		defer cancel()
	}

	payload, err := googleValidate(validateCtx, token, state.cfg.Audience)
	if err != nil {
		return nil, mapGoogleError(err)
	}
	if state.cfg.Issuer != "" && !strings.EqualFold(payload.Issuer, state.cfg.Issuer) {
		return nil, newError(ErrCodeInvalidIssuer, fmt.Errorf("issuer mismatch: got %s, want %s", payload.Issuer, state.cfg.Issuer))
	}

	claims := claimsFromGooglePayload(payload)
	if !state.subjectAllowed(claims) {
		return nil, newError(ErrCodeSubjectNotAllowed, fmt.Errorf("subject %q not allowed", claims.Subject))
	}

	return claims, nil
}

func (v *Validator) lookupIssuer(name string) (*issuerState, bool) {
	if name == "" {
		name = v.defaultIssuer
	}
	if name == "" {
		return nil, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	state, ok := v.issuers[name]
	return state, ok
}

func (s *issuerState) subjectAllowed(claims *Claims) bool {
	if len(s.allowedSubjects) == 0 {
		return true
	}
	subjectKey := strings.ToLower(claims.Subject)
	if _, ok := s.allowedSubjects[subjectKey]; ok {
		return true
	}
	if claims.Email != "" {
		if _, ok := s.allowedSubjects[strings.ToLower(claims.Email)]; ok {
			return true
		}
	}
	return false
}

func toSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		set[strings.ToLower(v)] = struct{}{}
	}
	return set
}

func extractJWKSClaims(token jwt.Token) *Claims {
	private := token.PrivateClaims()
	var audience []string
	if audList := token.Audience(); len(audList) > 0 {
		audience = append([]string(nil), audList...)
	}
	claims := &Claims{
		Subject:   token.Subject(),
		Issuer:    token.Issuer(),
		Audience:  audience,
		ExpiresAt: token.Expiration(),
		NotBefore: token.NotBefore(),
		IssuedAt:  token.IssuedAt(),
		JWTID:     token.JwtID(),
	}

	if v, ok := token.Get("email"); ok {
		if s, ok := v.(string); ok {
			claims.Email = strings.ToLower(s)
		}
	}
	if v, ok := private["role"]; ok {
		if s, ok := v.(string); ok {
			claims.Role = s
		}
	}
	if v, ok := private["session_id"]; ok {
		if s, ok := v.(string); ok {
			claims.SessionID = s
		}
	}
	if len(private) > 0 {
		claims.CustomClaims = make(map[string]any, len(private))
		for k, v := range private {
			claims.CustomClaims[k] = v
		}
	}
	populateKnownClaims(claims)
	return claims
}

func claimsFromGooglePayload(payload *idtoken.Payload) *Claims {
	var audience []string
	if aud := payload.Audience; aud != "" {
		audience = []string{aud}
	}
	claims := &Claims{
		Subject:   payload.Subject,
		Issuer:    payload.Issuer,
		Audience:  audience,
		ExpiresAt: time.Unix(payload.Expires, 0).UTC(),
		IssuedAt:  time.Unix(payload.IssuedAt, 0).UTC(),
	}
	if payload.Claims != nil {
		claims.CustomClaims = make(map[string]any, len(payload.Claims))
		for k, v := range payload.Claims {
			claims.CustomClaims[k] = v
		}
		if email, ok := payload.Claims["email"].(string); ok {
			claims.Email = strings.ToLower(email)
		}
		if role, ok := payload.Claims["role"].(string); ok {
			claims.Role = role
		}
		if sessionID, ok := payload.Claims["session_id"].(string); ok {
			claims.SessionID = sessionID
		}
	}
	populateKnownClaims(claims)
	return claims
}

func mapGoogleError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "audience provided does not match"):
		return newError(ErrCodeInvalidAudience, err)
	case strings.Contains(msg, "token expired"):
		return newError(ErrCodeExpired, err)
	case strings.Contains(msg, "could not find matching cert"):
		return newError(ErrCodeInvalidToken, err)
	case strings.Contains(msg, "invalid token"):
		return newError(ErrCodeInvalidToken, err)
	case strings.Contains(msg, "unable to decode JWT"):
		return newError(ErrCodeInvalidToken, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ErrCodeJWKSUnavailable, err)
	}
	return newError(ErrCodeInvalidToken, err)
}

func classifyJWKSValidationError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "token expired") || strings.Contains(lower, `"exp" not satisfied`):
		return newError(ErrCodeExpired, err)
	case strings.Contains(lower, `"nbf" not satisfied`):
		return newError(ErrCodeNotYetValid, err)
	}
	return nil
}

func populateKnownClaims(claims *Claims) {
	if claims.CustomClaims == nil {
		return
	}
	if scopes, ok := claims.CustomClaims["scopes"]; ok {
		claims.Scopes = normalizeScopes(scopes)
	}
	if appMeta, ok := claims.CustomClaims["app_metadata"]; ok {
		if m := toMap(appMeta); m != nil {
			claims.AppMetadata = m
		}
	}
	if userMeta, ok := claims.CustomClaims["user_metadata"]; ok {
		if m := toMap(userMeta); m != nil {
			claims.UserMetadata = m
		}
	}
}

func normalizeScopes(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
		return nil
	default:
		return nil
	}
}

func toMap(value any) map[string]any {
	switch m := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	default:
		return nil
	}
}
