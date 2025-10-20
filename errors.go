package jwtx

import "fmt"

// ErrorCode represents validator error categories.
type ErrorCode string

const (
	ErrCodeInvalidToken        ErrorCode = "invalid_token"
	ErrCodeExpired             ErrorCode = "token_expired"
	ErrCodeNotYetValid         ErrorCode = "token_not_yet_valid"
	ErrCodeInvalidIssuer       ErrorCode = "invalid_issuer"
	ErrCodeInvalidAudience     ErrorCode = "invalid_audience"
	ErrCodeSubjectNotAllowed   ErrorCode = "subject_not_allowed"
	ErrCodeIssuerNotRegistered ErrorCode = "issuer_not_registered"
	ErrCodeJWKSUnavailable     ErrorCode = "jwks_unavailable"
	ErrCodeInternal            ErrorCode = "internal_error"
)

var errorMessages = map[ErrorCode]string{
	ErrCodeInvalidToken:        "Invalid token",
	ErrCodeExpired:             "Token expired",
	ErrCodeNotYetValid:         "Token not yet valid",
	ErrCodeInvalidIssuer:       "Invalid issuer",
	ErrCodeInvalidAudience:     "Invalid audience",
	ErrCodeSubjectNotAllowed:   "Subject not allowed",
	ErrCodeIssuerNotRegistered: "Issuer not registered",
	ErrCodeJWKSUnavailable:     "JWKS unavailable",
	ErrCodeInternal:            "Internal error",
}

// Error wraps validator errors with a stable code and message.
type Error struct {
	Code    ErrorCode
	Message string
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	base := e.Message
	if base == "" {
		base = string(e.Code)
	}
	if e.Err == nil {
		return base
	}
	return fmt.Sprintf("%s: %v", base, e.Err)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

func newError(code ErrorCode, err error) error {
	msg, ok := errorMessages[code]
	if !ok {
		msg = string(code)
	}
	return &Error{Code: code, Message: msg, Err: err}
}
