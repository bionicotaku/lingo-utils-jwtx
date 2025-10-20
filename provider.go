package jwtx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"
)

// TokenFactory allows callers to override how Identity Tokens are minted.
type TokenFactory func(context.Context, string, ProviderParams) (oauth2.TokenSource, error)

// ProviderConfig defines how tokens should be issued by default.
type ProviderConfig struct {
	ServiceAccount string
	IncludeEmail   bool
	Delegates      []string
	TokenFactory   TokenFactory
}

// Provider issues Google Identity Tokens for service-to-service calls.
// It caches token sources per (audience, service account, includeEmail, delegates) combination.
type Provider struct {
	mu       sync.RWMutex
	factory  TokenFactory
	entries  map[providerKey]*tokenSourceEntry
	defaults ProviderParams
}

type providerKey struct {
	Audience       string
	ServiceAccount string
	IncludeEmail   bool
	Delegates      string
}

type tokenSourceEntry struct {
	source oauth2.TokenSource
}

type ProviderParams struct {
	ServiceAccount string
	IncludeEmail   bool
	Delegates      []string
}

// TokenOption customizes the behaviour for a single Token call.
type TokenOption func(*ProviderParams)

// WithServiceAccount overrides the service account used to mint the token.
func WithServiceAccount(email string) TokenOption {
	return func(p *ProviderParams) {
		p.ServiceAccount = email
	}
}

// WithIncludeEmail controls whether the resulting token contains the email claim.
func WithIncludeEmail(include bool) TokenOption {
	return func(p *ProviderParams) {
		p.IncludeEmail = include
	}
}

// WithDelegates sets the impersonation delegation chain.
func WithDelegates(delegates ...string) TokenOption {
	return func(p *ProviderParams) {
		p.Delegates = append([]string(nil), delegates...)
	}
}

// NewProvider constructs a Provider using the supplied defaults.
func NewProvider(cfg ProviderConfig) *Provider {
	factory := cfg.TokenFactory
	if factory == nil {
		factory = defaultFactory
	}
	return &Provider{
		factory: factory,
		entries: make(map[providerKey]*tokenSourceEntry),
		defaults: ProviderParams{
			ServiceAccount: cfg.ServiceAccount,
			IncludeEmail:   cfg.IncludeEmail,
			Delegates:      append([]string(nil), cfg.Delegates...),
		},
	}
}

// Token returns an identity token for the given audience.
func (p *Provider) Token(ctx context.Context, audience string, opts ...TokenOption) (string, error) {
	if strings.TrimSpace(audience) == "" {
		return "", errors.New("audience is required")
	}

	params := cloneParams(p.defaults)
	for _, opt := range opts {
		opt(&params)
	}

	key := providerKey{
		Audience:       audience,
		ServiceAccount: params.ServiceAccount,
		IncludeEmail:   params.IncludeEmail,
		Delegates:      strings.Join(params.Delegates, ","),
	}

	entry, err := p.getOrCreate(ctx, key, params)
	if err != nil {
		return "", err
	}

	tok, err := entry.source.Token()
	if err != nil {
		return "", fmt.Errorf("fetch token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("empty access token returned")
	}
	return tok.AccessToken, nil
}

func (p *Provider) getOrCreate(ctx context.Context, key providerKey, params ProviderParams) (*tokenSourceEntry, error) {
	p.mu.RLock()
	entry, ok := p.entries[key]
	p.mu.RUnlock()
	if ok {
		return entry, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok = p.entries[key]; ok {
		return entry, nil
	}

	ts, err := p.factory(persistentContext(ctx), key.Audience, params)
	if err != nil {
		return nil, err
	}
	entry = &tokenSourceEntry{source: oauth2.ReuseTokenSource(nil, ts)}
	p.entries[key] = entry
	return entry, nil
}

func defaultFactory(ctx context.Context, audience string, params ProviderParams) (oauth2.TokenSource, error) {
	if params.ServiceAccount != "" {
		cfg := impersonate.IDTokenConfig{
			Audience:        audience,
			TargetPrincipal: params.ServiceAccount,
			IncludeEmail:    params.IncludeEmail,
			Delegates:       params.Delegates,
		}
		return impersonate.IDTokenSource(ctx, cfg)
	}
	return idtoken.NewTokenSource(ctx, audience)
}

func cloneParams(in ProviderParams) ProviderParams {
	out := in
	if len(in.Delegates) > 0 {
		out.Delegates = append([]string(nil), in.Delegates...)
	}
	return out
}

func persistentContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	if _, ok := ctx.(*detachedContext); ok {
		return ctx
	}
	return &detachedContext{parent: ctx}
}

type detachedContext struct {
	parent context.Context
}

func (d *detachedContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (d *detachedContext) Done() <-chan struct{} {
	return nil
}

func (d *detachedContext) Err() error {
	return nil
}

func (d *detachedContext) Value(key any) any {
	if d.parent == nil {
		return nil
	}
	return d.parent.Value(key)
}
