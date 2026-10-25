package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const Issuer = "https://token.actions.githubusercontent.com"
const JWKSURL = Issuer + "/.well-known/jwks"

type Config struct {
	Audience           string   `json:"audience"`
	AppID              string   `json:"app_id"`
	InstallationID     int64    `json:"installation_id"`
	TargetRepositoryID int64    `json:"target_repository_id"`
	Policies           []Policy `json:"policies"`
}

// Every policy is an exact match. Separate policies express separate grants.
type Policy struct {
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Repository        string `json:"repository"`
	Ref               string `json:"ref"`
	EventName         string `json:"event_name"`
	WorkflowRef       string `json:"workflow_ref"`
	JobWorkflowRef    string `json:"job_workflow_ref,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	var c Config
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("unexpected data after config")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	u, err := url.Parse(c.Audience)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("audience must be an absolute HTTPS URL without credentials, query or fragment")
	}
	if c.AppID == "" || c.InstallationID <= 0 || c.TargetRepositoryID <= 0 || len(c.Policies) == 0 {
		return errors.New("app_id, positive installation_id/target_repository_id and policies are required")
	}
	for i, p := range c.Policies {
		if !positiveID(p.RepositoryID) || !positiveID(p.RepositoryOwnerID) || strings.Count(p.Repository, "/") != 1 ||
			!strings.HasPrefix(p.Ref, "refs/heads/") ||
			!strings.HasPrefix(p.WorkflowRef, p.Repository+"/.github/workflows/") ||
			!strings.HasSuffix(p.WorkflowRef, "@"+p.Ref) {
			return fmt.Errorf("policy %d requires repository IDs, a branch and an exact workflow_ref on that branch", i)
		}
		switch p.EventName {
		case "push", "workflow_dispatch", "workflow_run", "schedule", "release":
		default:
			return fmt.Errorf("policy %d: unsupported event (PR events are never permitted)", i)
		}
	}
	return nil
}

func positiveID(s string) bool { n, err := strconv.ParseInt(s, 10, 64); return err == nil && n > 0 }
