package jwtx

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type fakeFactory struct {
	count int32
	err   error
}

func (f *fakeFactory) call(_ context.Context, audience string, params ProviderParams) (oauth2.TokenSource, error) {
	if f.err != nil {
		return nil, f.err
	}
	atomic.AddInt32(&f.count, 1)
	tokenValue := audience + ":" + params.ServiceAccount
	tok := &oauth2.Token{AccessToken: tokenValue, Expiry: time.Now().Add(time.Hour)}
	return oauth2.StaticTokenSource(tok), nil
}

func TestProviderTokenCaching(t *testing.T) {
	factory := &fakeFactory{}
	provider := NewProvider(ProviderConfig{TokenFactory: factory.call})

	ctx := context.Background()
	token, err := provider.Token(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Token error: %v", err)
	}
	if token != "aud-1:" {
		t.Fatalf("unexpected token: %s", token)
	}

	token, err = provider.Token(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Token second call: %v", err)
	}
	if token != "aud-1:" {
		t.Fatalf("unexpected token second call: %s", token)
	}
	if got := atomic.LoadInt32(&factory.count); got != 1 {
		t.Fatalf("expected factory invoked once, got %d", got)
	}

	// Different service account should create new entry.
	_, err = provider.Token(ctx, "aud-1", WithServiceAccount("svc@example.com"))
	if err != nil {
		t.Fatalf("Token with service account: %v", err)
	}
	if got := atomic.LoadInt32(&factory.count); got != 2 {
		t.Fatalf("expected factory invoked twice, got %d", got)
	}
}

func TestProviderFactoryError(t *testing.T) {
	expected := errors.New("no credentials")
	factory := &fakeFactory{err: expected}
	provider := NewProvider(ProviderConfig{TokenFactory: factory.call})

	_, err := provider.Token(context.Background(), "aud")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderDefaultConfig(t *testing.T) {
	provider := NewProvider(ProviderConfig{})
	ctx := context.Background()
	// defaultFactory will attempt to use idtoken.NewTokenSource which in tests may fail.
	_, err := provider.Token(ctx, "aud")
	if err == nil {
		t.Fatalf("expected error when metadata unavailable")
	}
}

func TestProviderTokenIgnoresCanceledContextForRefresh(t *testing.T) {
	var (
		factoryCalls int32
		tokenCalls   int32
	)

	provider := NewProvider(ProviderConfig{
		TokenFactory: func(ctx context.Context, audience string, params ProviderParams) (oauth2.TokenSource, error) {
			atomic.AddInt32(&factoryCalls, 1)
			return &contextBoundTokenSource{
				ctx:        ctx,
				tokenValue: fmt.Sprintf("%s-token", audience),
				callCount:  &tokenCalls,
			}, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	token, err := provider.Token(ctx, "aud")
	if err != nil {
		t.Fatalf("Token initial call: %v", err)
	}
	if token == "" {
		t.Fatal("expected token value, got empty string")
	}

	cancel()

	token, err = provider.Token(context.Background(), "aud")
	if err != nil {
		t.Fatalf("Token second call after cancel: %v", err)
	}
	if token == "" {
		t.Fatal("expected token value on second call")
	}

	if got := atomic.LoadInt32(&factoryCalls); got != 1 {
		t.Fatalf("expected factory invoked once, got %d", got)
	}
	if got := atomic.LoadInt32(&tokenCalls); got < 2 {
		t.Fatalf("expected underlying token source invoked at least twice, got %d", got)
	}
}

type contextBoundTokenSource struct {
	ctx        context.Context
	tokenValue string
	callCount  *int32
}

func (s *contextBoundTokenSource) Token() (*oauth2.Token, error) {
	if s.callCount != nil {
		atomic.AddInt32(s.callCount, 1)
	}
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	default:
	}
	return &oauth2.Token{
		AccessToken: s.tokenValue,
		Expiry:      time.Now().Add(-time.Minute),
	}, nil
}
