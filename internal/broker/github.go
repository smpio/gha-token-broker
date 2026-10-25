package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Minter interface {
	Mint(context.Context) (Token, error)
}

type GitHub struct {
	Config  Config
	Key     *rsa.PrivateKey
	Client  *http.Client
	baseURL string // Tests only; production always uses api.github.com.
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM private key")
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	} else {
		return nil, errors.New("expected RSA private key")
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 {
		return nil, errors.New("expected valid RSA private key of at least 2048 bits")
	}
	return key, key.Validate()
}

func (g *GitHub) appJWT() (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	b, err := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "iss": g.Config.AppID})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.Key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (g *GitHub) Mint(ctx context.Context) (Token, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return Token{}, err
	}
	// Never inherit all installation permissions/repositories, even if the App
	// installation is broadened later. Clients cannot override this body.
	body, _ := json.Marshal(map[string]any{
		"repository_ids": []int64{g.Config.TargetRepositoryID},
		"permissions":    map[string]string{"contents": "write"},
	})
	base := g.baseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/app/installations/%d/access_tokens", base, g.Config.InstallationID), bytes.NewReader(body))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "smpio/gha-token-broker")
	resp, err := g.Client.Do(req)
	if err != nil {
		return Token{}, errors.New("GitHub request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Token{}, fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	var result Token
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return Token{}, errors.New("invalid GitHub response")
	}
	if result.Token == "" || !result.ExpiresAt.After(time.Now()) {
		return Token{}, errors.New("invalid GitHub token or expiry")
	}
	return result, nil
}
