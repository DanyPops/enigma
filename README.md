# @danypops/enigma

Encrypted credential vault and supervisor daemon. Holds delegated OAuth/API
credentials for other daemons (GitHub, GitLab, Jira, Jenkins, ...) and
injects them as environment variables into spawned child processes. Neither
the child daemons nor anything talking to them ever sees the vault's
storage, encryption, or refresh machinery — that's an intra-service
concern, not something exposed as a tool or capability to an AI agent or
any other consumer.

## Why this exists

Multiple daemons in this workspace (pipes, tickets, and future ones) each
authenticate to the same handful of external platforms — GitHub, GitLab,
Jira. Each one was independently building its own OAuth device-flow
mechanics, token storage, and refresh logic. Enigma centralizes that:
one place stores credentials, refreshes them, and hands them to whichever
consumer daemon needs them, via process supervision rather than a shared
library each daemon imports.

The isolation goal is specific: a consumer daemon (and anything that calls
into it, including an AI agent) should never hold, see, or be able to
introspect the raw credential. It reads `process.env.GITHUB_TOKEN` exactly
as it always has — it just doesn't know, and never needs to know, that the
value came from an encrypted vault rather than a `.env` file.

## Install

```bash
bun install
enigma login jenkins   # or github, gitlab — see below
enigma supervisor      # serves the vault and spawns configured units
```

## Master key

Two paths, tried in order — the key hierarchy is not a secret worth hiding:

1. **OS keyring** (primary) — the real native keychain (Secret
   Service/D-Bus on Linux, Keychain on macOS, Credential Manager on
   Windows), via [`@napi-rs/keyring`](https://github.com/Brooooooklyn/keyring-node)
   (the actively maintained NAPI binding; `node-keytar`, the older common
   choice, was last published 2022-02-17 and is effectively abandoned).
   Generated lazily on first use, no prompt.
2. **File-based key** (automatic fallback) — `$XDG_STATE_HOME/enigma/.master`
   at `0600`, for headless machines or any environment with no reachable
   keyring backend.

A passphrase-prompted third option is explicitly out of scope — it doesn't
fit a systemd-supervised, non-interactive process.

## Credential storage

One AES-256-GCM-encrypted file per backend under
`$XDG_STATE_HOME/enigma/credentials/<backend>.json`. GCM's authentication
tag makes "wrong master key" and "tampered file" the same failure mode —
decryption throws rather than silently returning garbage.

## CLI

```
enigma serve                     serve the vault only, no supervision
enigma supervisor [--config <path>]
                                  serve the vault and spawn configured daemons
enigma login <github|gitlab|jenkins>
                                  authenticate and store credentials for a backend
enigma login jira [--site <name-or-url>] [--scope <scope>]
                                  Jira Cloud OAuth 2.0 (3LO), via JIRA_CLIENT_ID/JIRA_CLIENT_SECRET
enigma login google [--scope <scope>]
                                  Drive/Docs OAuth device flow, via GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET
enigma login oidc --name <name> --issuer <url> --client-id <id> [--scope <scope>] [--env-var <VAR_NAME>]
                                  generic OIDC device flow for any compliant provider
enigma rotate <backend>           force a refresh of a stored credential
enigma revoke <backend>           delete a stored credential
enigma list                       list backends with a stored credential
enigma health                     talk to a running instance, print status JSON
```

All OAuth/OIDC mechanics (discovery, device-flow polling, refresh) run
through [`openid-client`](https://github.com/panva/openid-client) (OpenID
Certified — Basic, FAPI 1.0, FAPI 2.0), not hand-rolled protocol code.
GitHub has no OIDC discovery at all (confirmed: `.well-known/openid-configuration`
404s) — its `Configuration` is built from its two fixed, documented
endpoints. GitLab supports discovery for its general server metadata, but
its own discovery document always reports `device_authorization_endpoint`
as `null` even on instances that advertise `device_code` as a supported
grant type (confirmed live on two independent instances — a genuine GitLab
inconsistency, not an assumption); the endpoint is patched in from GitLab's
documented conventional path after discovery. Any other OIDC-compliant
provider goes through `enigma login oidc` with pure discovery and zero
backend-specific code.

### The generic OIDC backend — no company or product ever named in source

`enigma login oidc` is how an organization's own SSO (or any other
OIDC-compliant identity provider — Okta, Auth0, or an organization's own,
whatever) becomes usable, without a single line of enigma source code referencing it. The
backend name, issuer URL, and client ID are all operator-supplied at
runtime:

```bash
enigma login oidc --name my-company-sso --issuer https://sso.example.com/realms/employees --client-id my-app
```

The env var a spawned unit sees defaults to `<NAME>_TOKEN` (sanitized,
uppercased) or can be set explicitly with `--env-var`. Refresh works
automatically for any backend logged in this way — capability is resolved
from what the stored credential's own metadata carries (`issuerUrl` +
`clientId`), not from a fixed name registry, so a new generic backend
never needs new enigma code to support rotation.

`login` runs entirely client-side against each backend's own OAuth or
credential mechanics, writing directly into the same encrypted store the
daemon reads — it works even before a daemon has ever been started, and an
already-running daemon picks up a freshly logged-in credential on its very
next request (the token provider re-reads the store fresh every time), no
restart needed.

### Registering an OAuth App per backend

Neither GitHub nor GitLab supports self-service dynamic client
registration (confirmed: GitLab's own Dynamic Client Registration support
is an open, unimplemented feature request as of this writing). A one-time,
human, per-instance registration step is unavoidable:

- **GitHub**: `github.com/settings/developers` → OAuth Apps → New OAuth
  App → enable Device Flow. Set `GITHUB_CLIENT_ID` before running
  `enigma login github`.
- **GitLab**: your instance's User Settings → Applications (or Admin Area
  → Applications for an instance-wide app everyone on a team can share).
  Set `GITLAB_URL` and `GITLAB_CLIENT_ID` before running
  `enigma login gitlab`. This pass only implements the Device
  Authorization Grant — the Authorization Code+PKCE fallback needed for
  older self-managed instances predating the device grant is an explicit,
  flagged gap, not built here yet.
- **Jenkins**: no OAuth exists. Generate an API token from your Jenkins
  user's Configure page, then set `JENKINS_URL`, `JENKINS_USER`,
  `JENKINS_API_TOKEN` before running `enigma login jenkins`.
- **Jira Cloud**: register an OAuth 2.0 (3LO) app at
  `developer.atlassian.com/console/myapps`, enable OAuth 2.0 (3LO), and
  set the app's Callback URL to `http://127.0.0.1:8976/callback` (or a
  different port of your choosing, matched by `JIRA_CALLBACK_PORT`).
  Jira Cloud's OAuth is authorization-code only — there is no device flow
  — and PKCE support is flag-gated per app by Atlassian support rather
  than universally available, so this uses the documented, always-available
  confidential-client path instead: set `JIRA_CLIENT_ID` and
  `JIRA_CLIENT_SECRET` before running `enigma login jira`. Include
  `offline_access` in `--scope`/`JIRA_SCOPES` to get a refresh token —
  without it the credential can't be renewed and will need a fresh login
  once the access token expires. If the app is authorized against more
  than one Jira site, pass `--site <name-or-url>` to disambiguate.
- **Google**: register an OAuth client at
  `console.cloud.google.com/apis/credentials` (Desktop app / TV and
  Limited Input Devices type), enable the Drive API and Docs API for the
  project, then set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` before
  running `enigma login google`. Unlike GitHub/GitLab's genuinely
  public-client device flow, Google's token endpoint requires the
  client_secret even for device-flow clients (confirmed via its own
  discovery document). Defaults to Drive + Docs scope; override with
  `--scope`/`GOOGLE_SCOPES`. **A client left in "Testing" publishing
  status (the normal case for personal use, since full verification
  requires a Google security assessment) has refresh tokens that expire
  after 7 days regardless of use** — without going through verification,
  expect to re-run `enigma login google` about weekly. This is a raw
  bearer-token model for direct REST calls to Drive/Docs
  (`GOOGLE_ACCESS_TOKEN`), not an Application Default Credentials file —
  it does not make a consumer daemon auto-discoverable by GCP
  infrastructure SDKs (Cloud Storage, BigQuery, Vertex AI, etc.).

GitHub's classic OAuth App device-flow tokens never expire and issue no
refresh token (confirmed against GitHub's own docs — the example device-
flow response has no `refresh_token` field at all; refresh is a
GitHub-App-only feature). GitLab, Jira Cloud, and Google all issue refresh
tokens — Jira's rotate (each refresh invalidates the one just used and
returns a new one); GitLab's and Google's persist unless the server
chooses to rotate them (Google's still expire outright after 7 days in
Testing status, independent of rotation).

## Supervisor config

`$XDG_STATE_HOME/enigma/daemons.json` (override with `--config`):

```json
{
	"units": [
		{
			"name": "pipes",
			"bin": "/path/to/pipes-daemon/src/cli.ts",
			"args": ["serve"],
			"backends": ["github", "gitlab"],
			"restart": "on-failure"
		}
	]
}
```

Each unit's listed `backends` are resolved from the vault and injected as
env (`GITHUB_TOKEN`, `GITLAB_TOKEN`/`GITLAB_URL`, `JIRA_API_TOKEN`/`JIRA_URL`,
`JENKINS_API_TOKEN`/`JENKINS_USER`/`JENKINS_URL`, `GOOGLE_ACCESS_TOKEN`) before spawning. Every
other known credential env var name is explicitly blanked for that unit,
even if ambiently present on enigma's own process — a unit only ever
receives the credentials its own `backends` list requested, never
whatever else happens to be set in enigma's environment.

Restart policy (`always` | `on-failure` | `no`, default `no`) governs
unplanned exits. A credential nearing expiry triggers a restart with
fresh env regardless of restart policy — that's enigma's own decision to
refresh, not a crash. Killing the supervisor sends SIGTERM to every
spawned child and waits for all of them to exit before it exits itself.

## Boundaries enforced

- **Enigma never imports pipes/tickets/web-spider.** It knows backend
  *names* ("github", "gitlab", "jira", "jenkins", "google") and the
  generic credential shape, never a consumer daemon's internal
  orchestration.
- **Consumer daemons never import enigma.** They read
  `process.env.GITHUB_TOKEN` like always, and can be started standalone
  with `GITHUB_TOKEN=... bun pipes-daemon/src/cli.ts serve` for local
  hacking with no enigma involved at all.
- **Nothing exposes vault operations as an agent-callable tool.** No MCP
  server, no vault-specific tool output. An AI agent calling into a
  consumer daemon sees only that daemon's own domain operations.

## Development

```bash
bun install
bun test
bun x tsc --noEmit
```

## License

MIT
