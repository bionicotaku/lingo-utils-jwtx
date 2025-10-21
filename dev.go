package jwtx

// DevBypassClaims holds attributes used when issuing synthetic claims in dev mode.
type DevBypassClaims struct {
	Subject  string
	Issuer   string
	Audience []string
	Email    string
}

// ToCallerClaims converts the dev bypass configuration into caller claims.
func (d DevBypassClaims) ToCallerClaims() CallerClaims {
	claims := &Claims{
		Subject:  d.Subject,
		Issuer:   d.Issuer,
		Audience: append([]string(nil), d.Audience...),
		Email:    d.Email,
	}
	return CallerClaims{
		Claims:    claims,
		DevBypass: true,
	}
}

// DefaultDevBypassClaims returns a baseline set of claims suitable for local development.
func DefaultDevBypassClaims(audience string) DevBypassClaims {
	aud := audience
	if aud == "" {
		aud = "https://dev.local"
	}
	return DevBypassClaims{
		Subject:  "dev-bypass",
		Issuer:   "jwtx.dev",
		Audience: []string{aud},
	}
}
