package broker

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Claims struct {
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Repository        string `json:"repository"`
	Ref               string `json:"ref"`
	EventName         string `json:"event_name"`
	WorkflowRef       string `json:"workflow_ref"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
	IssuedAt          int64  `json:"iat"`
	NotBefore         int64  `json:"nbf"`
	ExpiresAt         int64  `json:"exp"`
	Subject           string `json:"sub"`
}

type Verifier interface {
	Verify(context.Context, string) (Claims, error)
}

type OIDCVerifier struct{ verifier *oidc.IDTokenVerifier }

func NewOIDCVerifier(ctx context.Context, audience string, client *http.Client) *OIDCVerifier {
	// Fixed issuer/JWKS URL: a caller cannot direct discovery to another host.
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), JWKSURL)
	return &OIDCVerifier{oidc.NewVerifier(Issuer, keys, &oidc.Config{
		ClientID: audience, SupportedSigningAlgs: []string{"RS256"},
	})}
}

func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Claims, error) {
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, errors.New("invalid OIDC token")
	}
	var c Claims
	if err := token.Claims(&c); err != nil {
		return c, errors.New("invalid OIDC claims")
	}
	// Require bounded, recent GitHub credentials in addition to the library's
	// signature, issuer, audience and expiry checks. No expiry grace period.
	now := time.Now().Unix()
	if c.Subject == "" || c.IssuedAt <= 0 || c.NotBefore <= 0 || c.ExpiresAt <= now ||
		c.IssuedAt > now+30 || c.NotBefore > now+30 || now-c.IssuedAt > 600 ||
		c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 600 || !positiveID(c.RunID) || !positiveID(c.RunAttempt) {
		return c, errors.New("invalid OIDC lifetime or run identity")
	}
	return c, nil
}

func (p Policy) Allows(c Claims) bool {
	return p.RepositoryID == c.RepositoryID && p.RepositoryOwnerID == c.RepositoryOwnerID &&
		p.Repository == c.Repository && p.Ref == c.Ref && p.EventName == c.EventName &&
		p.WorkflowRef == c.WorkflowRef && (p.JobWorkflowRef == "" || p.JobWorkflowRef == c.JobWorkflowRef)
}
