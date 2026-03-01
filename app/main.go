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
			Help: "Total number of HTTP requests by method, path, and status.",
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
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(loginAttemptsTotal)
	prometheus.MustRegister(activeConnections)
}

// --- Rate limiter (per-IP, simple token bucket) ---

type rateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientState
	rate     int // requests allowed per window
	window   time.Duration
}

type clientState struct {
	count    int
	resetAt  time.Time
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

// --- Middleware ---

func metricsMiddleware(next http.HandlerFunc, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next(rw, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rw.status)

		httpRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
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
		ip := strings.Split(r.RemoteAddr, ":")[0]
		// Respect X-Forwarded-For when behind a proxy
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = strings.Split(fwd, ",")[0]
		}
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, "429").Inc()
			return
		}
		next(w, r)
	}
}

// --- Handlers ---

func handleRoot(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Hello from devops-lab!",
		"hostname": hostname,
		"version":  getEnv("APP_VERSION", "v0.1.0"),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// Fake login — accepts only hardcoded credentials, useful for brute-force demo
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"token": "fake-jwt-token-abc123"})
	} else {
		loginAttemptsTotal.WithLabelValues("failure").Inc()
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
	}
}

// Admin endpoint — should be protected; intentionally left open for demo
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "Bearer fake-jwt-token-abc123" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users":   []string{"admin", "alice", "bob"},
		"secrets": "super-secret-data",
	})
}

// Slow endpoint — useful for simulating load and seeing latency metrics
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

	// Rate limiter: 60 requests per minute per IP (for normal endpoints)
	// Login endpoint gets a stricter limiter: 5 attempts per minute
	globalRL := newRateLimiter(60, time.Minute)
	loginRL := newRateLimiter(5, time.Minute)

	mux := http.NewServeMux()

	mux.HandleFunc("/", metricsMiddleware(rateLimitMiddleware(globalRL, handleRoot), "/"))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/slow", metricsMiddleware(rateLimitMiddleware(globalRL, handleSlow), "/slow"))
	mux.HandleFunc("/admin", metricsMiddleware(rateLimitMiddleware(globalRL, handleAdmin), "/admin"))
	mux.HandleFunc("/login", metricsMiddleware(rateLimitMiddleware(loginRL, handleLogin), "/login"))
	mux.Handle("/metrics", promhttp.Handler())

	log.Printf("devops-lab starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
