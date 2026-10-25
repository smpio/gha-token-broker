package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{Audience: "https://broker.test", AppID: "123", InstallationID: 456, TargetRepositoryID: 789,
		Policies: []Policy{{RepositoryID: "11", RepositoryOwnerID: "22", Repository: "owner/app", Ref: "refs/heads/master",
			EventName: "workflow_run", WorkflowRef: "owner/app/.github/workflows/deploy.yml@refs/heads/master"}}}
}

func validClaims() Claims {
	p := validConfig().Policies[0]
	return Claims{RepositoryID: p.RepositoryID, RepositoryOwnerID: p.RepositoryOwnerID, Repository: p.Repository,
		Ref: p.Ref, EventName: p.EventName, WorkflowRef: p.WorkflowRef, RunID: "100", RunAttempt: "1"}
}

func TestPolicy(t *testing.T) {
	p := validConfig().Policies[0]
	if !p.Allows(validClaims()) {
		t.Fatal("valid policy denied")
	}
	for _, field := range []string{"repository_id", "repository_owner_id", "repository", "ref", "event_name", "workflow_ref", "job_workflow_ref"} {
		t.Run(field, func(t *testing.T) {
			c := validClaims()
			var obj map[string]any
			b, _ := json.Marshal(c)
			_ = json.Unmarshal(b, &obj)
			obj[field] = "other"
			b, _ = json.Marshal(obj)
			_ = json.Unmarshal(b, &c)
			policy := p
			if field == "job_workflow_ref" {
				policy.JobWorkflowRef = "owner/shared/.github/workflows/deploy.yml@refs/heads/master"
			}
			if policy.Allows(c) {
				t.Fatal("unauthorized claims accepted")
			}
		})
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func signedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	b, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwtClaims() map[string]any {
	c := validClaims()
	b, _ := json.Marshal(c)
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	now := time.Now().Unix()
	obj["iss"] = Issuer
	obj["aud"] = "https://broker.test"
	obj["sub"] = "repo:owner/app:ref:refs/heads/master"
	obj["iat"] = now
	obj["nbf"] = now - 1
	obj["exp"] = now + 300
	return obj
}

func TestOIDCSignatureClaimsAndRotation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var active atomic.Int64
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		k, kid := key, "one"
		if active.Load() == 2 {
			k, kid = other, "two"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()
	client := &http.Client{Timeout: time.Second, Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != JWKSURL {
			t.Errorf("unexpected discovery URL: %s", r.URL)
		}
		copy := r.Clone(r.Context())
		copy.URL, _ = url.Parse(jwks.URL)
		return http.DefaultTransport.RoundTrip(copy)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v := NewOIDCVerifier(ctx, "https://broker.test", client)
	for i := 0; i < 2; i++ {
		if _, err := v.Verify(ctx, signedJWT(t, key, "one", jwtClaims())); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("JWKS should be cached")
	}
	cases := []struct {
		name, field string
		value       any
	}{
		{"issuer", "iss", "https://attacker.test"}, {"audience", "aud", "https://other.test"},
		{"expired", "exp", time.Now().Unix() - 1}, {"future_nbf", "nbf", time.Now().Unix() + 120},
		{"future_iat", "iat", time.Now().Unix() + 120}, {"old_iat", "iat", time.Now().Unix() - 700},
		{"long_lifetime", "exp", time.Now().Unix() + 3600}, {"missing_iat", "iat", 0},
		{"missing_nbf", "nbf", 0}, {"missing_run_id", "run_id", ""}, {"missing_sub", "sub", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwtClaims()
			claims[tc.field] = tc.value
			if _, err := v.Verify(ctx, signedJWT(t, key, "one", claims)); err == nil {
				t.Fatal("invalid JWT accepted")
			}
		})
	}
	if _, err := v.Verify(ctx, signedJWT(t, other, "one", jwtClaims())); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := v.Verify(ctx, "eyJhbGciOiJub25lIn0.e30."); err == nil {
		t.Fatal("unsigned token accepted")
	}
	active.Store(2)
	if _, err := v.Verify(ctx, signedJWT(t, other, "two", jwtClaims())); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
}

type fakeVerifier struct {
	claims Claims
	err    error
}

func (v fakeVerifier) Verify(context.Context, string) (Claims, error) { return v.claims, v.err }

type fakeMinter struct {
	calls int
	err   error
}

func (m *fakeMinter) Mint(context.Context) (Token, error) {
	m.calls++
	return Token{Token: "ghs_sensitive", ExpiresAt: time.Now().Add(time.Hour)}, m.err
}

func TestExchangeAuthorizationAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, auth, body, query string
		claims                  Claims
		verifyErr, mintErr      error
		status, calls           int
	}{
		{name: "ok", auth: "Bearer jwt", claims: validClaims(), status: 200, calls: 1},
		{name: "missing_auth", claims: validClaims(), status: 401},
		{name: "forged", auth: "Bearer jwt", verifyErr: errors.New("bad signature"), status: 401},
		{name: "unauthorized", auth: "Bearer jwt", claims: Claims{RepositoryID: "other"}, status: 403},
		{name: "scope_override_body", auth: "Bearer jwt", body: `{"repository_ids":[1]}`, claims: validClaims(), status: 400},
		{name: "scope_override_query", auth: "Bearer jwt", query: "?repository=other", claims: validClaims(), status: 400},
		{name: "upstream", auth: "Bearer jwt", claims: validClaims(), mintErr: errors.New("GitHub unavailable"), status: 502, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			m := &fakeMinter{err: tc.mintErr}
			s := NewServer(validConfig(), fakeVerifier{tc.claims, tc.verifyErr}, m, slog.New(slog.NewJSONHandler(&logs, nil)))
			r := httptest.NewRequest("POST", "/v1/token"+tc.query, strings.NewReader(tc.body))
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || m.calls != tc.calls {
				t.Fatalf("status %d, mint calls %d: %s", w.Code, m.calls, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("token response must not be cached")
			}
			if tc.status == 200 {
				var token Token
				if json.Unmarshal(w.Body.Bytes(), &token) != nil || token.Token != "ghs_sensitive" {
					t.Fatal("missing token")
				}
			}
			if strings.Contains(logs.String(), "ghs_sensitive") || strings.Contains(logs.String(), "Bearer jwt") {
				t.Fatal("credential logged")
			}
		})
	}
}

func TestRateLimitAndHealth(t *testing.T) {
	m := &fakeMinter{}
	s := NewServer(validConfig(), fakeVerifier{claims: validClaims()}, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.Handler()
	for i := 0; i < 21; i++ {
		r := httptest.NewRequest("POST", "/v1/token", nil)
		r.Header.Set("Authorization", "Bearer jwt")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 200
		if i == 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d status %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("health rate limited")
	}
}

func TestGitHubScopeAndJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/app/installations/456/access_tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.RepositoryIDs) != 1 || body.RepositoryIDs[0] != 789 || len(body.Permissions) != 1 || body.Permissions["contents"] != "write" {
			t.Errorf("unexpected scope: %+v", body)
		}
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			t.Fatal("missing app JWT")
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Error(err)
		}
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Iss      string `json:"iss"`
			Exp, Iat int64
		}
		if json.Unmarshal(payload, &claims) != nil || claims.Iss != "123" || claims.Exp <= time.Now().Unix() || claims.Exp-claims.Iat > 600 {
			t.Error("invalid app JWT")
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(Token{Token: "ghs_test", ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer upstream.Close()
	g := GitHub{Config: validConfig(), Key: key, Client: upstream.Client(), baseURL: upstream.URL}
	if token, err := g.Mint(context.Background()); err != nil || token.Token != "ghs_test" {
		t.Fatalf("mint: %+v %v", token, err)
	}
}

func TestConfigFailsClosed(t *testing.T) {
	for _, edit := range []func(*Config){
		func(c *Config) { c.TargetRepositoryID = 0 }, func(c *Config) { c.InstallationID = 0 },
		func(c *Config) { c.Audience = "http://broker.test" }, func(c *Config) { c.Policies = nil },
		func(c *Config) { c.Policies[0].EventName = "pull_request_target" },
		func(c *Config) { c.Policies[0].RepositoryOwnerID = "" },
		func(c *Config) { c.Policies[0].WorkflowRef = "*" },
		func(c *Config) { c.Policies[0].Ref = "refs/pull/1/merge" },
	} {
		c := validConfig()
		edit(&c)
		if c.Validate() == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(validConfig())
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"app_id"`), []byte(`"typo"`), 1)
	_ = os.WriteFile(path, b, 0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown config field accepted")
	}
}
