package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Existing tests ---

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", body["status"])
	}
}

func TestHandleReady(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleRoot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	handleRoot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["message"] == "" {
		t.Error("expected non-empty message")
	}
	if body["version"] == "" {
		t.Error("expected version in response")
	}
}

func TestHandleLogin_Success(t *testing.T) {
	payload := `{"username":"admin","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:9999"
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["token"] == "" {
		t.Error("expected token in response")
	}
}

func TestHandleLogin_Failure(t *testing.T) {
	payload := `{"username":"admin","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.2:9999"
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAdmin_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	handleAdmin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAdmin_Authorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer fake-jwt-token-abc123")
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	handleAdmin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)

	for i := range 3 {
		if !rl.allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Error("4th request should be rate limited")
	}
	if !rl.allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestHandleSlow(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/slow?ms=50", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()

	start := time.Now()
	handleSlow(w, req)
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("expected at least 50ms delay, got %v", elapsed)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- New mitigation tests ---

func TestBlockedSensitivePaths(t *testing.T) {
	paths := []string{
		"/.env",
		"/.git/config",
		"/.git/HEAD",
		"/admin/users",
		"/admin/",
		"/../etc/passwd",
		"/%2e%2e/etc/passwd",
		"/wp-config.php",
		"/backup.sql",
	}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "1.2.3.4:9999"
		w := httptest.NewRecorder()
		handleRoot(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("path %q: expected 404, got %d", path, w.Code)
		}
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/some/unknown/path", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	handleRoot(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", w.Code)
	}
}

func TestIsSensitivePath(t *testing.T) {
	blocked := []string{"/.env", "/.git/config", "/admin/users", "/../etc/passwd", "/%2e%2e/shadow"}
	for _, p := range blocked {
		if !isSensitivePath(p) {
			t.Errorf("expected %q to be flagged as sensitive", p)
		}
	}
	allowed := []string{"/", "/health", "/ready", "/slow", "/admin", "/login", "/metrics"}
	for _, p := range allowed {
		if isSensitivePath(p) {
			t.Errorf("expected %q NOT to be flagged as sensitive", p)
		}
	}
}

func TestLoginLockout(t *testing.T) {
	// Use a fresh lockout with low threshold for testing
	ll := newLoginLockout(3, time.Minute)
	ip := "9.9.9.9"

	if ll.isLocked(ip) {
		t.Error("IP should not be locked initially")
	}

	// Record 3 failures — should trigger lockout on the 3rd
	ll.recordFailure(ip)
	ll.recordFailure(ip)
	if ll.isLocked(ip) {
		t.Error("IP should not be locked after 2 failures")
	}
	ll.recordFailure(ip)
	if !ll.isLocked(ip) {
		t.Error("IP should be locked after 3 failures")
	}

	// Verify fail count
	if ll.failCount(ip) != 3 {
		t.Errorf("expected failCount=3, got %d", ll.failCount(ip))
	}

	// Success clears the lockout
	ll.recordSuccess(ip)
	if ll.isLocked(ip) {
		t.Error("IP should be unlocked after successful login")
	}
}

func TestLockoutMiddlewareBlocks(t *testing.T) {
	// Create a fresh lockout, lock an IP, verify middleware returns 429
	saved := globalLockout
	defer func() { globalLockout = saved }()

	globalLockout = newLoginLockout(1, time.Minute)
	ip := "8.8.8.8"
	globalLockout.recordFailure(ip) // 1 failure = locked (maxFails=1)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"x","password":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":9999"
	w := httptest.NewRecorder()

	lockoutMiddleware(handleLogin)(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 from lockout, got %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeadersMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection":       "1; mode=block",
	}
	for header, expected := range headers {
		if got := w.Header().Get(header); got != expected {
			t.Errorf("header %s: expected %q, got %q", header, expected, got)
		}
	}
	if w.Header().Get("Server") != "" {
		t.Error("Server header should be empty to avoid fingerprinting")
	}
}
