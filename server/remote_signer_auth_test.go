package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// testJWKSServer wraps an httptest server and an RSA key pair for testing JWKS validation.
type testJWKSServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

// newTestJWKSServer creates a mock JWKS endpoint with a generated RSA key pair.
func newTestJWKSServer(t *testing.T) *testJWKSServer {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"

	// Create JWKS response
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"n":   base64urlEncode(privateKey.PublicKey.N.Bytes()),
				"e":   base64urlEncode(bigIntToBytes(int64(privateKey.PublicKey.E))),
				"alg": "RS256",
			},
		},
	}

	// Create HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	return &testJWKSServer{
		server:     server,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        kid,
	}
}

func (s *testJWKSServer) close() {
	s.server.Close()
}

func (s *testJWKSServer) url() string {
	return s.server.URL
}

// makeTestToken creates a signed JWT token with the given claims using the test RSA key.
func (s *testJWKSServer) makeTestToken(t *testing.T, claims remoteSignerClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.privateKey)
	require.NoError(t, err)
	return signed
}

// validClaims returns a baseline valid claims struct for tests.
func validClaims() remoteSignerClaims {
	return remoteSignerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
			Issuer:    "https://livepeer.ai",
			Audience:  jwt.ClaimStrings{expectedAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "test-jti-001",
		},
		Scope:          "sign:orchestrator sign:payment sign:byoc",
		SpendingCapWei: "1000000000000000000",
		Tier:           "standard",
	}
}

// Helper functions for encoding JWKS
func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func bigIntToBytes(n int64) []byte {
	if n == 0 {
		return []byte{0}
	}
	bytes := make([]byte, 0, 8)
	for n > 0 {
		bytes = append([]byte{byte(n & 0xff)}, bytes...)
		n >>= 8
	}
	return bytes
}

func TestNewJWTValidator_MissingJWKSUrl(t *testing.T) {
	_, err := newJWTValidator(&RemoteSignerAuthConfig{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be set")
}

func TestNewJWTValidator_JWKS(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	v, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotNil(t, v.keyFunc)
	require.NotNil(t, v.jwks)
	defer v.close()
}

func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	tokenStr := jwksServer.makeTestToken(t, claims)

	// Handler that checks the user was set in context
	var capturedUser string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/sign-orchestrator-info", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, claims.Subject, capturedUser)
}

func TestJWTAuthMiddleware_MissingAuthHeader(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/sign-orchestrator-info", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "missing or malformed")
}

func TestJWTAuthMiddleware_MalformedAuthHeader(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "just-a-token"},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer only", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := jwtAuthMiddleware(validator, inner)
			req := httptest.NewRequest("POST", "/test", nil)
			req.Header.Set("Authorization", tt.header)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			require.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}

func TestJWTAuthMiddleware_ExpiredToken(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	tokenStr := jwksServer.makeTestToken(t, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for expired token")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid or expired")
}

func TestJWTAuthMiddleware_WrongAudience(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{"wrong-audience"}
	tokenStr := jwksServer.makeTestToken(t, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for wrong audience")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid or expired")
}

func TestJWTAuthMiddleware_WrongSigningKey(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	// Create a second JWKS server with a different key
	jwksServer2 := newTestJWKSServer(t)
	defer jwksServer2.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	// Sign with the wrong key
	tokenStr := jwksServer2.makeTestToken(t, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for wrong signing key")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestJWTAuthMiddleware_MissingSubject(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	claims.Subject = "" // empty subject
	tokenStr := jwksServer.makeTestToken(t, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for missing subject")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "missing subject")
}

func TestJWTAuthMiddleware_MalformedToken(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt.token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestUserFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, "", UserFromContext(ctx))
}

func TestUserFromContext_WithValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyUserEthAddr, "0xABC123")
	require.Equal(t, "0xABC123", UserFromContext(ctx))
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer mytoken123", "mytoken123"},
		{"bearer lowercase", "bearer mytoken123", "mytoken123"},
		{"empty header", "", ""},
		{"no bearer prefix", "mytoken123", ""},
		{"basic auth", "Basic dXNlcjpwYXNz", ""},
		{"bearer with spaces", "Bearer   mytoken123  ", "mytoken123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			result := extractBearerToken(req)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestJWTAuthMiddleware_CustomClaims(t *testing.T) {
	jwksServer := newTestJWKSServer(t)
	defer jwksServer.close()

	validator, err := newJWTValidator(&RemoteSignerAuthConfig{
		JWKSUrl: jwksServer.url(),
	})
	require.NoError(t, err)
	defer validator.close()

	claims := validClaims()
	claims.Scope = "sign:orchestrator"
	claims.SpendingCapWei = "5000000000000000000"
	claims.Tier = "premium"
	tokenStr := jwksServer.makeTestToken(t, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		require.Equal(t, claims.Subject, user)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"user": user})
	})

	handler := jwtAuthMiddleware(validator, inner)
	req := httptest.NewRequest("POST", "/sign-orchestrator-info", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}
