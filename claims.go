package jwtx

import "time"

// Claims represents normalized JWT claims shared across issuers.
type Claims struct {
    Subject   string
    Issuer    string
    Audience  []string
    ExpiresAt time.Time
    NotBefore time.Time
    IssuedAt  time.Time
    JWTID     string

    Email        string
    Role         string
    SessionID    string
    CustomClaims map[string]any

    Scopes       []string
    AppMetadata  map[string]any
    UserMetadata map[string]any
}
