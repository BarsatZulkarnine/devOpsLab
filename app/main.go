package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// --- Prometheus metrics ---

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, path, and status.",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	loginAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total login attempts by result (success/failure).",
		},
		[]string{"result"},
	)

	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_connections",
		Help: "Current number of active HTTP connections.",
	})

	// NEW: security-specific metrics
	blockedPathsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocked_paths_total",
			Help: "Requests to blocked sensitive paths — indicates recon/traversal attempts.",
		},
		[]string{"path"},
	)

	loginLockoutsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "login_lockouts_total",
		Help: "Number of IPs locked out due to repeated login failures.",
	})
)

func init() {
	prometheus.MustRegister(httpRequestsTotal, httpRequestDuration,
		loginAttemptsTotal, activeConnections,
		blockedPathsTotal, loginLockoutsTotal)
}

// --- Sensitive paths to block (returns 404, not 401 — don't confirm they exist) ---

var sensitivePathPrefixes = []string{
	"/.env", "/.git", "/.ssh", "/.htaccess",
	"/wp-config", "/phpinfo", "/backup", "/dump",
	"/config.json", "/config.yaml", "/config.yml",
	"/admin/users", "/admin/",
	"/etc/", "/proc/",
}

func isSensitivePath(path string) bool {
	lp := strings.ToLower(path)
	// Block path traversal characters
	if strings.Contains(lp, "..") || strings.Contains(lp, "%2e%2e") || strings.Contains(lp, "%252e") {
		return true
	}
	for _, prefix := range sensitivePathPrefixes {
		if lp == prefix || strings.HasPrefix(lp, prefix) {
			return true
		}
	}
	return false
}

// --- Rate limiter (per-IP, sliding window) ---

type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientState
	rate    int
	window  time.Duration
}

type clientState struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		clients: make(map[string]*clientState),
		rate:    rate,
		window:  window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cs, exists := rl.clients[ip]
	if !exists || now.After(cs.resetAt) {
		rl.clients[ip] = &clientState{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if cs.count >= rl.rate {
		return false
	}
	cs.count++
	return true
}

func (rl *rateLimiter) cleanup() {
	for range time.Tick(time.Minute) {
		rl.mu.Lock()
		now := time.Now()
		for ip, cs := range rl.clients {
			if now.After(cs.resetAt) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// --- Login lockout (per-IP, hard block after N failures) ---

type loginLockout struct {
	mu       sync.Mutex
	failures map[string]*lockoutState
	maxFails int
	lockDur  time.Duration
}

type lockoutState struct {
	count    int
	lockedAt time.Time
}

func newLoginLockout(maxFails int, lockDur time.Duration) *loginLockout {
	ll := &loginLockout{
		failures: make(map[string]*lockoutState),
		maxFails: maxFails,
		lockDur:  lockDur,
	}
	go ll.cleanup()
	return ll
}

func (ll *loginLockout) isLocked(ip string) bool {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	s, ok := ll.failures[ip]
	if !ok {
		return false
	}
	if s.count < ll.maxFails {
		return false
	}
	if time.Since(s.lockedAt) > ll.lockDur {
		delete(ll.failures, ip)
		return false
	}
	return true
}

func (ll *loginLockout) recordFailure(ip string) {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	s, ok := ll.failures[ip]
	if !ok {
		s = &lockoutState{}
		ll.failures[ip] = s
	}
	s.count++
	if s.count == ll.maxFails {
		s.lockedAt = time.Now()
		loginLockoutsTotal.Inc()
		log.Printf("[SECURITY] IP %s locked out after %d failed login attempts", ip, ll.maxFails)
	}
}

func (ll *loginLockout) recordSuccess(ip string) {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	delete(ll.failures, ip)
}

func (ll *loginLockout) failCount(ip string) int {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	if s, ok := ll.failures[ip]; ok {
		return s.count
	}
	return 0
}

func (ll *loginLockout) cleanup() {
	for range time.Tick(5 * time.Minute) {
		ll.mu.Lock()
		for ip, s := range ll.failures {
			if s.count >= ll.maxFails && time.Since(s.lockedAt) > ll.lockDur {
				delete(ll.failures, ip)
			}
		}
		ll.mu.Unlock()
	}
}

// globalLockout is initialised before main so tests can call handlers directly.
var globalLockout = newLoginLockout(5, 15*time.Minute)

// --- Middleware ---

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Server", "")
		next.ServeHTTP(w, r)
	})
}

func metricsMiddleware(next http.HandlerFunc, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next(rw, r)

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rw.status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(time.Since(start).Seconds())
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"rate limit exceeded"}`)
			httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, "429").Inc()
			return
		}
		next(w, r)
	}
}

func lockoutMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if globalLockout.isLocked(ip) {
			w.Header().Set("Retry-After", "900")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"too many failed attempts — locked for 15 minutes"}`)
			httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, "429").Inc()
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		return host[:idx]
	}
	return host
}

// --- Handlers ---

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// ServeMux routes "/" as a catch-all — any unregistered path lands here.
	// Block sensitive paths with 404 (don't confirm they exist with 401/403).
	if r.URL.Path != "/" {
		if isSensitivePath(r.URL.Path) {
			path := r.URL.Path
			if len(path) > 50 {
				path = path[:50]
			}
			blockedPathsTotal.WithLabelValues(path).Inc()
			log.Printf("[SECURITY] blocked sensitive path %q from %s", r.URL.Path, clientIP(r))
		}
		http.NotFound(w, r)
		return
	}
	hostname, _ := os.Hostname()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Hello from devops-lab!",
		"hostname": hostname,
		"version":  getEnv("APP_VERSION", "v0.2.0"),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// handleLogin — hardened with per-IP lockout after 5 failures (15 min block).
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if creds.Username == "admin" && creds.Password == "secret123" {
		loginAttemptsTotal.WithLabelValues("success").Inc()
		globalLockout.recordSuccess(ip)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"token": "fake-jwt-token-abc123"})
		return
	}

	loginAttemptsTotal.WithLabelValues("failure").Inc()
	globalLockout.recordFailure(ip)
	remaining := globalLockout.maxFails - globalLockout.failCount(ip)
	if remaining < 0 {
		remaining = 0
	}
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":              "invalid credentials",
		"attempts_remaining": remaining,
	})
}

// handleAdmin — protected; sub-paths are blocked at the root catch-all.
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "Bearer fake-jwt-token-abc123" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": []string{"admin", "alice", "bob"},
	})
}

// handleSlow — artificial latency for load testing.
func handleSlow(w http.ResponseWriter, r *http.Request) {
	delay := 500 * time.Millisecond
	if d := r.URL.Query().Get("ms"); d != "" {
		if ms, err := strconv.Atoi(d); err == nil && ms > 0 && ms <= 5000 {
			delay = time.Duration(ms) * time.Millisecond
		}
	}
	time.Sleep(delay)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("responded after %v", delay),
	})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	port := getEnv("PORT", "8080")

	globalRL := newRateLimiter(60, time.Minute)
	loginRL := newRateLimiter(10, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/", metricsMiddleware(rateLimitMiddleware(globalRL, handleRoot), "/"))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/slow", metricsMiddleware(rateLimitMiddleware(globalRL, handleSlow), "/slow"))
	mux.HandleFunc("/admin", metricsMiddleware(rateLimitMiddleware(globalRL, handleAdmin), "/admin"))
	mux.HandleFunc("/login", metricsMiddleware(
		rateLimitMiddleware(loginRL, lockoutMiddleware(handleLogin)),
		"/login",
	))
	mux.Handle("/metrics", promhttp.Handler())

	log.Printf("devops-lab v0.2.0 starting on :%s (mitigations: path-blocking, login-lockout, security-headers)", port)
	log.Fatal(http.ListenAndServe(":"+port, securityHeadersMiddleware(mux)))
}
