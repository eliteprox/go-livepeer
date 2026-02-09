package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/glog"
)

// RemoteSignerAuthConfig holds the configuration for JWT-based authentication
// on the remote signer.
type RemoteSignerAuthConfig struct {
	// JWKSUrl is the JWKS endpoint for asymmetric JWT verification.
	// Example: https://livepeer.ai/.well-known/jwks.json
	JWKSUrl string
}

// remoteSignerClaims represents the expected JWT claims from the auth website.
type remoteSignerClaims struct {
	jwt.RegisteredClaims

	// Scope defines allowed operations, e.g. "sign:orchestrator sign:payment sign:byoc"
	Scope string `json:"scope,omitempty"`

	// SpendingCapWei is the per-session spending limit in wei (informational, not yet enforced)
	SpendingCapWei string `json:"spending_cap_wei,omitempty"`

	// Tier is the user's service tier, e.g. "standard", "premium"
	Tier string `json:"tier,omitempty"`
}

// jwtValidator wraps the key function used to validate JWT signatures using JWKS.
type jwtValidator struct {
	keyFunc jwt.Keyfunc
	jwks    *keyfunc.JWKS
}

// close releases resources held by the validator (JWKS background refresh goroutine).
func (v *jwtValidator) close() {
	if v.jwks != nil {
		v.jwks.EndBackground()
	}
}

// newJWTValidator creates a jwtValidator from the given auth config.
// It returns an error if the config is invalid or JWKS initialization fails.
func newJWTValidator(cfg *RemoteSignerAuthConfig) (*jwtValidator, error) {
	if cfg.JWKSUrl == "" {
		return nil, fmt.Errorf("-remoteSignerJWKSUrl must be set")
	}
	return newJWKSValidator(cfg.JWKSUrl)
}

// newJWKSValidator initializes a JWKS-based validator that fetches and caches
// public keys from the given endpoint with automatic background refresh.
func newJWKSValidator(jwksURL string) (*jwtValidator, error) {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval: 1 * time.Hour,
		RefreshTimeout:  30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	glog.Infof("Initialized JWKS validator from %s", jwksURL)
	return &jwtValidator{
		keyFunc: jwks.Keyfunc,
		jwks:    jwks,
	}, nil
}

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey int

const (
	// ctxKeyUserEthAddr is the context key for the authenticated user's ETH address (from JWT sub).
	ctxKeyUserEthAddr contextKey = iota
)

// UserFromContext extracts the authenticated user's ETH address from the request context.
// Returns an empty string if no user is authenticated.
func UserFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUserEthAddr).(string); ok {
		return v
	}
	return ""
}

// expectedAudience is the required JWT audience claim value.
const expectedAudience = "livepeer-remote-signer"

// jwtAuthMiddleware returns HTTP middleware that validates JWT bearer tokens.
// Requests without a valid token receive a 401 Unauthorized response.
func jwtAuthMiddleware(validator *jwtValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractBearerToken(r)
		if tokenStr == "" {
			http.Error(w, `{"error":"missing or malformed Authorization header"}`, http.StatusUnauthorized)
			return
		}

		claims := &remoteSignerClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, validator.keyFunc,
			jwt.WithAudience(expectedAudience),
			jwt.WithIssuedAt(),
		)
		if err != nil || !token.Valid {
			glog.Warningf("JWT validation failed: %v", err)
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		sub := claims.Subject
		if sub == "" {
			http.Error(w, `{"error":"token missing subject claim"}`, http.StatusUnauthorized)
			return
		}

		// Attach user identity to context for downstream handlers
		ctx := context.WithValue(r.Context(), ctxKeyUserEthAddr, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearerToken pulls the token from the Authorization: Bearer <token> header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
