# gha-token-broker

A small Go service that exchanges GitHub Actions OIDC identity for a GitHub App
installation token. Deployment logic stays in the calling workflow. The broker
does not clone repositories, change manifests or run Git commands.

## Trust and API

`POST /v1/token`, with `Authorization: Bearer <GitHub OIDC JWT>`, returns:

```json
{"token":"ghs_...","expires_at":"2026-10-25T12:00:00Z"}
```

No request body or query parameters are accepted. The target repository and the
`contents: write` permission are fixed by the operator. The App's other grants
are never inherited. GitHub implicitly includes repository metadata access.
The token can change all repository contents; it has no directory restrictions.
It does not have `workflows: write`, administration or access to other repositories.

The broker verifies RS256 signatures against GitHub's fixed JWKS endpoint,
issuer, audience, expiry, issued-at and not-before. GitHub signing keys are cached
and refreshed on rotation by `coreos/go-oidc`. Every allow rule matches the
immutable repository/owner IDs, repository name, branch, event and exact workflow
reference. An optional `job_workflow_ref` further restricts reusable workflows.
PR events are never allowed. Unknown fields or incomplete rules fail startup.

An OIDC token can be exchanged more than once during its validity. The broker is
stateless and does not promise single-use JWTs. Requests are limited to 60/minute
with burst 20 and four concurrent exchanges **per process**, before verification.
There is no automatic retry of token issuance. If the response is lost, an issued
token may remain valid until expiry. Use ingress limits for public traffic.

Responses are `no-store`. Logs contain verified repository/run IDs and issuance
outcomes, never credentials. Configure ingress/APM to avoid capturing
Authorization headers, response bodies or the mounted private key.

`GET /healthz` is a local liveness/readiness check. It does not call GitHub;
GitHub outages do not cause restart loops. Token issuance returns 502 on upstream
failure, 401 on invalid identity, 403 on a denied policy and 429 on overload.

## GitHub Action

The public repository contains the action at its root, including bundled `dist/`
files; callers need neither npm install nor a checkout of this repository.
Publish the repository, release `v1.0.0` and point the action alias `v1` at that
release before using the following example.
Prefer an immutable commit SHA once the release is available.

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: smpio/gha-token-broker@v1
    id: infra-auth
    with:
      broker-url: https://gha-token-broker.bind.pw

  - uses: actions/checkout@v4
    with:
      repository: smpio/infra
      ref: master
      token: ${{ steps.infra-auth.outputs.token }}
      path: infra

  # Existing YAML editing, commit and push steps follow here.
```

`broker-url` is public configuration, not a secret. Its canonical form without a
trailing slash is the OIDC audience, which must exactly match server configuration.
Only HTTPS is accepted and redirects are refused. Outputs: `token`, `expires-at`.

The action masks credentials, saves the installation token for cleanup and
revokes it directly at GitHub in an `always()` post step. It has no skip-revoke
option. If the runner is killed or cleanup cannot reach GitHub, the token expires
in approximately one hour. Cleanup failure fails the job. Use the token in the
same job, for less than an hour; do not upload it as an artifact or job output.
Cleanup order lets `actions/checkout` remove its persisted credential first.

Only run the credential-bearing job on trusted code. Build/test in another job;
do not execute PR code, downloaded executables, untrusted scripts or arbitrary
workflow artifacts after acquiring the token. OIDC authenticates the calling job,
not the provenance of an image or the success of a preceding build.

## Server configuration

Create a **dedicated GitHub App** with repository `Contents: Read and write`.
Disable webhooks and install it on **only** `smpio/infra`. No organization grants,
OAuth callback, Actions or Workflows write permission are needed. Do not reuse
the ARC App. Record the App ID (or client ID), installation ID and download a PEM
private key. Keep it outside Git and container build context.

Copy `examples/smpio.json` to `config.json` and replace the App/installation IDs.
Its zero installation ID intentionally prevents starting an unfinished setup.
Repository IDs in the example were verified against GitHub:

| Resource | ID |
| --- | --- |
| Organization `smpio` | `29103864` |
| Caller `smpio/kube-resource-analyzer` | `229058900` |
| Target `smpio/infra` | `138051827` |

The pilot grants only `k8s-deploy.yml` on `master` for `workflow_run` and
`workflow_dispatch`. For `workflow_run`, OIDC describes the deployment workflow
on the default branch. Validation of the upstream build's repository, branch and
conclusion stays in the workflow. No environment is required; authorization uses
individual signed claims rather than assumptions about the subject string.

Configuration is read at startup. Restart the broker after policy/key changes.
Removing a rule prevents new tokens; existing tokens remain valid until revoked
or expired. Uninstall/restrict the App or revoke tokens for emergency withdrawal.

```sh
go build -o gha-token-broker ./cmd/gha-token-broker
GOMEMLIMIT=40MiB GOMAXPROCS=1 ./gha-token-broker \
  -config config.json -private-key /secure/path/private-key.pem -listen :8080
```

TLS terminates at ingress. Do not expose the plain HTTP port directly outside
the trusted network. The process needs outbound HTTPS to
`token.actions.githubusercontent.com` and `api.github.com`, plus DNS.

## Container and Kubernetes preparation

`Dockerfile` builds a static binary and copies it plus CA certificates into
`scratch`. It runs as UID 65532, with `GOMEMLIMIT=40MiB` and `GOMAXPROCS=1`.
The example deployment sets a 64 MiB memory limit. `GOMEMLIMIT` is a soft Go heap
budget, not an RSS cap; validate memory with real concurrent exchanges before
choosing a production limit. No database, persistent volume or sidecar is needed.

The image workflow publishes `ghcr.io/smpio/gha-token-broker:latest`, commit tags
and semver/major tags. Make the GHCR package public after its first publication
so Kubernetes can pull it without credentials. Use a released major tag or
immutable digest for rollout, after the initial image has been published.

`examples/kubernetes.yaml` is a preparation template, **not an installed resource**.
It uses the proposed hostname `gha-token-broker.bind.pw`, nginx ingress and the
existing `letsencrypt-http01` issuer. DNS, GitHub App, image, namespace, config and
Secret must exist before rollout. Desired cluster manifests belong in `smpio/infra`
when adding this workload is explicitly authorized; do not maintain a second
GitOps source in this repository.

To prepare the configuration resources locally (these commands do not apply them):

```sh
kubectl -n gha-token-broker create configmap gha-token-broker-config \
  --from-file=config.json=config.json --dry-run=client -o yaml > /tmp/broker-config.yaml
kubectl -n gha-token-broker create secret generic gha-token-broker-key \
  --from-file=private-key.pem=/secure/path/private-key.pem --dry-run=client -o yaml > /secure/path/broker-secret.yaml
```

Never commit the generated Secret. Mount the key using the template's fsGroup
and permissions; do not pass its contents in command arguments or environment.

## Pilot activation order

1. Publish the public repository, tag `v1.0.0` (which publishes container tag `1`)
   and point the action alias `v1` at the same commit.
2. Create/install the dedicated App; configure DNS/TLS and deploy the broker with
   the pilot policy and its private key. Verify health and denied identities.
3. Review and push the prepared KRA workflow change only after the broker is ready.
   That workflow updates automatically synchronized `infra/kube/` configuration;
   follow the infrastructure repository's required diff review/approval for the
   activation push. The migration itself is not evidence of deployment.
4. Run the pilot, verify the infra commit and token cleanup, then remove the old
   `INFRA_REPO_TOKEN` repository secret. Keep the old secret until the pilot passes.

## Development

```sh
go test -race ./...
go vet ./...
npm ci
npm test
npm run build
```

Commit `go.sum`, `package-lock.json` and generated `dist/`. CI rebuilds the action
and checks for differences. Tests use generated RSA keys, a local JWKS server
and fake GitHub endpoints; they do not need GitHub credentials or mint real tokens.

References: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation),
[Actions toolkit](https://github.com/actions/toolkit/tree/main/packages/core).
