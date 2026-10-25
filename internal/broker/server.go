package broker

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Config   Config
	Verifier Verifier
	Minter   Minter
	Logger   *slog.Logger
	mu       sync.Mutex
	tokens   float64
	last     time.Time
	slots    chan struct{}
}

func NewServer(c Config, v Verifier, m Minter, logger *slog.Logger) *Server {
	return &Server{Config: c, Verifier: v, Minter: m, Logger: logger, tokens: 20, last: time.Now(), slots: make(chan struct{}, 4)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/token", s.exchange)
	return mux
}

func (s *Server) allowRequest() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.tokens = min(20, s.tokens+now.Sub(s.last).Seconds()) // 60/minute, burst 20, across all callers.
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "request body and query parameters are not supported", http.StatusBadRequest)
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || len(auth[0]) > 24<<10 {
		http.Error(w, "OIDC bearer token required", http.StatusUnauthorized)
		return
	}
	if !s.allowRequest() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "broker busy", http.StatusTooManyRequests)
		return
	}
	c, err := s.Verifier.Verify(r.Context(), strings.TrimPrefix(auth[0], "Bearer "))
	if err != nil {
		http.Error(w, "invalid OIDC token", http.StatusUnauthorized)
		return
	}
	allowed := false
	for _, p := range s.Config.Policies {
		if p.Allows(c) {
			allowed = true
			break
		}
	}
	if !allowed {
		s.Logger.Warn("exchange denied", "repository_id", c.RepositoryID, "run_id", c.RunID)
		http.Error(w, "workflow is not authorized", http.StatusForbidden)
		return
	}
	token, err := s.Minter.Mint(r.Context())
	if err != nil {
		s.Logger.Error("token issuance failed", "error", err, "repository_id", c.RepositoryID, "run_id", c.RunID)
		http.Error(w, "GitHub token issuance failed", http.StatusBadGateway)
		return
	}
	s.Logger.Info("token issued", "repository_id", c.RepositoryID, "run_id", c.RunID, "run_attempt", c.RunAttempt, "target_repository_id", s.Config.TargetRepositoryID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(token); err != nil {
		s.Logger.Warn("token response could not be delivered", "run_id", c.RunID)
	}
}
