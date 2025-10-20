package jwtx

import (
	"errors"
	"fmt"
	"time"
)

const (
	defaultClockSkew    = 30 * time.Second
	defaultMinRefresh   = 5 * time.Minute
	defaultHTTPTimeout  = 5 * time.Second
	defaultGoogleIssuer = "https://accounts.google.com"
)

// ValidatorConfig describes all issuers the validator should trust.
type ValidatorConfig struct {
	Issuers []IssuerConfig
}

// IssuerConfig contains validation parameters for a specific issuer.
type IssuerConfig struct {
	Name            string
	JWKSURL         string
	Issuer          string
	Audience        string
	AllowedSubjects []string
	ClockSkew       time.Duration
	MinRefresh      time.Duration
	HTTPTimeout     time.Duration
}

// normalize sets default values for optional fields.
func (c *IssuerConfig) normalize() {
	if c.JWKSURL == "" && c.Issuer == "" {
		c.Issuer = defaultGoogleIssuer
	}
	if c.ClockSkew <= 0 {
		c.ClockSkew = defaultClockSkew
	}
	if c.MinRefresh <= 0 {
		c.MinRefresh = defaultMinRefresh
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = defaultHTTPTimeout
	}
}

// validate ensures the issuer configuration is usable.
func (c IssuerConfig) validate() error {
	switch {
	case c.Name == "":
		return errors.New("issuer name is required")
	case c.Audience == "":
		return errors.New("audience is required")
	case c.JWKSURL == "":
		// Google mode, issuer optional (defaults applied in normalize)
		return nil
	case c.Issuer == "":
		return errors.New("issuer claim expected value is required")
	}
	return nil
}

// issuerIndex returns the config mapped by issuer name.
func (c ValidatorConfig) issuerIndex() (map[string]IssuerConfig, error) {
	if len(c.Issuers) == 0 {
		return nil, errors.New("at least one issuer must be configured")
	}
	index := make(map[string]IssuerConfig, len(c.Issuers))
	for _, issuer := range c.Issuers {
		if err := issuer.validate(); err != nil {
			return nil, fmt.Errorf("issuer %q: %w", issuer.Name, err)
		}
		if _, exists := index[issuer.Name]; exists {
			return nil, fmt.Errorf("duplicate issuer name %q", issuer.Name)
		}
		clone := issuer
		clone.normalize()
		index[clone.Name] = clone
	}
	return index, nil
}
