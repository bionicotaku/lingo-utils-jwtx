package jwtx

import "context"

type callerClaimsKey struct{}

// CallerClaims represents the caller context stored during JWT validation.
type CallerClaims struct {
	Claims    *Claims
	DevBypass bool
}

// BindCallerClaims stores caller claims inside the context for downstream consumers.
func BindCallerClaims(ctx context.Context, claims CallerClaims) context.Context {
	return context.WithValue(ctx, callerClaimsKey{}, claims)
}

// CallerClaimsFromContext retrieves caller claims previously stored in the context.
func CallerClaimsFromContext(ctx context.Context) (CallerClaims, bool) {
	if ctx == nil {
		return CallerClaims{}, false
	}
	value := ctx.Value(callerClaimsKey{})
	if value == nil {
		return CallerClaims{}, false
	}
	claims, ok := value.(CallerClaims)
	return claims, ok
}
