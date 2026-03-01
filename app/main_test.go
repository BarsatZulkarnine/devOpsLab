package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
}

func TestHandleLogin_Success(t *testing.T) {
	payload := `{"username":"admin","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9999"
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
	req.RemoteAddr = "127.0.0.1:9999"
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

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Error("4th request should be rate limited")
	}
	// Different IP should still be allowed
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
