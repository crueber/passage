package csrf

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// ─── GenerateToken / ValidateToken unit tests ─────────────────────────────────

func TestGenerateToken_NonEmpty(t *testing.T) {
	tok, err := GenerateToken("signing-key")
	if err != nil {
		t.Fatalf("GenerateToken returned unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("GenerateToken returned an empty token")
	}
}

func TestValidateToken(t *testing.T) {
	const key = "test-signing-key"

	t.Run("accepts freshly generated token", func(t *testing.T) {
		tok, err := GenerateToken(key)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if err := ValidateToken(key, tok); err != nil {
			t.Errorf("expected valid token to be accepted, got: %v", err)
		}
	})

	t.Run("rejects empty token", func(t *testing.T) {
		if err := ValidateToken(key, ""); err == nil {
			t.Error("expected error for empty token, got nil")
		}
	})

	t.Run("rejects tampered token", func(t *testing.T) {
		tok, err := GenerateToken(key)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		// Flip the last byte of the base64 payload.
		payload, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("decode token: %v", err)
		}
		payload[len(payload)-1] ^= 0xFF
		tampered := base64.RawURLEncoding.EncodeToString(payload)

		if err := ValidateToken(key, tampered); err == nil {
			t.Error("expected error for tampered token, got nil")
		}
	})

	t.Run("rejects token signed with different key", func(t *testing.T) {
		tok, err := GenerateToken("other-signing-key")
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if err := ValidateToken(key, tok); err == nil {
			t.Error("expected error for token signed with different key, got nil")
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Build a token manually with a timestamp 5 hours in the past.
		nonce := make([]byte, 16)
		// nonce is zero — fine for this test.
		past := time.Now().Add(-5 * time.Hour).Unix()
		ts := make([]byte, 8)
		ts[0] = byte(past >> 56)
		ts[1] = byte(past >> 48)
		ts[2] = byte(past >> 40)
		ts[3] = byte(past >> 32)
		ts[4] = byte(past >> 24)
		ts[5] = byte(past >> 16)
		ts[6] = byte(past >> 8)
		ts[7] = byte(past)
		mac := hmacSign(key, append(nonce, ts...))
		payload := append(append(nonce, ts...), mac...)
		expired := base64.RawURLEncoding.EncodeToString(payload)

		if err := ValidateToken(key, expired); err == nil {
			t.Error("expected error for expired token, got nil")
		}
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		if err := ValidateToken(key, "not-valid-base64!!!"); err == nil {
			t.Error("expected error for malformed token, got nil")
		}
	})

	t.Run("rejects too-short decoded payload", func(t *testing.T) {
		short := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
		if err := ValidateToken(key, short); err == nil {
			t.Error("expected error for short payload, got nil")
		}
	})
}

// ─── TokenFromContext ──────────────────────────────────────────────────────────

func TestTokenFromContext(t *testing.T) {
	t.Run("returns empty string when not set", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := TokenFromContext(r.Context()); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("returns stored token", func(t *testing.T) {
		const want = "my-csrf-token"
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r = r.WithContext(withToken(r.Context(), want))
		if got := TokenFromContext(r.Context()); got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
}

// ─── ProtectAuthenticated middleware tests ────────────────────────────────────

func TestProtectAuthenticated(t *testing.T) {
	const sessionCookie = "passage_session"
	const sessionToken = "test-session-token-value"

	// nextHandler captures whether it was called and echoes back the CSRF token
	// stored in context (so we can verify the middleware sets it).
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		tok := TokenFromContext(r.Context())
		w.Header().Set("X-CSRF-Context-Token", tok)
		w.WriteHeader(http.StatusOK)
	})

	mw := ProtectAuthenticated(sessionCookie)
	handler := mw(next)

	t.Run("GET with session cookie sets token in context", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		tok := w.Header().Get("X-CSRF-Context-Token")
		if tok == "" {
			t.Error("expected non-empty CSRF token in context")
		}
		// Verify the token is validatable with the session token as key.
		if err := ValidateToken(sessionToken, tok); err != nil {
			t.Errorf("context token failed validation: %v", err)
		}
	})

	t.Run("GET without session cookie returns 403", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if nextCalled {
			t.Error("expected next handler NOT to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST with valid CSRF token calls next", func(t *testing.T) {
		nextCalled = false
		// First generate a valid token.
		tok, err := GenerateToken(sessionToken)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		form := url.Values{}
		form.Set(FieldName, tok)
		r := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("POST without CSRF token returns 403", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader("username=alice"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if nextCalled {
			t.Error("expected next handler NOT to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST with wrong CSRF token returns 403", func(t *testing.T) {
		nextCalled = false
		// Token signed with wrong key.
		tok, err := GenerateToken("wrong-key")
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		form := url.Values{}
		form.Set(FieldName, tok)
		r := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if nextCalled {
			t.Error("expected next handler NOT to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST with token in HX-CSRF-Token header calls next", func(t *testing.T) {
		nextCalled = false
		tok, err := GenerateToken(sessionToken)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		r := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(HeaderName, tok)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})
}

// ─── ProtectAnonymous middleware tests ────────────────────────────────────────

func TestProtectAnonymous(t *testing.T) {
	const cfgKey = "server-side-secret"

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		tok := TokenFromContext(r.Context())
		w.Header().Set("X-CSRF-Context-Token", tok)
		w.WriteHeader(http.StatusOK)
	})

	mw := ProtectAnonymous(cfgKey)
	handler := mw(next)

	t.Run("GET without CSRF cookie sets cookie and token in context", func(t *testing.T) {
		nextCalled = false
		r := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		// Verify a CSRF cookie was set.
		var csrfCookieVal string
		for _, c := range w.Result().Cookies() {
			if c.Name == CookieName {
				csrfCookieVal = c.Value
			}
		}
		if csrfCookieVal == "" {
			t.Error("expected CSRF cookie to be set")
		}
		// Verify context token is present and non-empty.
		tok := w.Header().Get("X-CSRF-Context-Token")
		if tok == "" {
			t.Error("expected non-empty CSRF token in context")
		}
	})

	t.Run("POST with valid CSRF token calls next", func(t *testing.T) {
		nextCalled = false
		// Generate a signing key with cfgKey mixed in.
		cookieVal := "randomcookievalue123"
		signingKey := cookieVal + "." + cfgKey

		tok, err := GenerateToken(signingKey)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		form := url.Values{}
		form.Set(FieldName, tok)
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("POST without CSRF token returns 403", func(t *testing.T) {
		nextCalled = false
		cookieVal := "randomcookievalue456"
		form := url.Values{}
		form.Set("username", "alice")
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if nextCalled {
			t.Error("expected next handler NOT to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST with wrong CSRF token returns 403", func(t *testing.T) {
		nextCalled = false
		cookieVal := "randomcookievalue789"
		// Sign with the wrong key.
		tok, err := GenerateToken("completely-wrong-key")
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		form := url.Values{}
		form.Set(FieldName, tok)
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if nextCalled {
			t.Error("expected next handler NOT to be called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST with token in HX-CSRF-Token header calls next", func(t *testing.T) {
		nextCalled = false
		cookieVal := "randomcookievalue-htmx"
		signingKey := cookieVal + "." + cfgKey

		tok, err := GenerateToken(signingKey)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(HeaderName, tok)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})
}

// ─── Integration test: middleware with chi router ─────────────────────────────

func TestProtectAuthenticated_Integration(t *testing.T) {
	const sessionCookie = "passage_session"
	const sessionToken = "integration-session-token"

	r := chi.NewRouter()
	r.Use(ProtectAuthenticated(sessionCookie))
	r.Get("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		tok := TokenFromContext(r.Context())
		w.Header().Set("X-CSRF-Token", tok)
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	t.Run("POST to admin without _csrf returns 403", func(t *testing.T) {
		form := url.Values{"username": {"alice"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("POST to admin with valid _csrf returns non-403", func(t *testing.T) {
		// First GET to obtain a token.
		getReq := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		getReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		getW := httptest.NewRecorder()
		r.ServeHTTP(getW, getReq)

		tok := getW.Header().Get("X-CSRF-Token")
		if tok == "" {
			t.Fatal("GET did not return a CSRF token")
		}

		// Now POST with that token.
		form := url.Values{
			"username": {"alice"},
			FieldName:  {tok},
		}
		postReq := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
		postW := httptest.NewRecorder()

		r.ServeHTTP(postW, postReq)

		if postW.Code == http.StatusForbidden {
			t.Errorf("expected non-403, got %d", postW.Code)
		}
	})
}
