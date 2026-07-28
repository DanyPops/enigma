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

Enigma pins one master-key provider in
`$XDG_STATE_HOME/enigma/master-key.json`. Provider failure stops startup;
Enigma never falls back to another key.

Linux desktops default to the freedesktop Secret Service. Install a Secret
Service implementation plus `secret-tool` (`libsecret-tools` on Debian;
`libsecret` on Fedora) and unlock the login collection before first use.

macOS defaults to Keychain Services, and Windows defaults to Credential
Manager. Both are tied to the current user's login/logon session — a
locked or unavailable store fails startup rather than falling back.

On macOS, reads go through the `security` CLI (bounded by a 10-second
subprocess timeout) rather than a direct native call: retrieving an
existing item's secret *value* has been confirmed, on real GitHub-hosted
macOS CI, to hang indefinitely at the OS level whenever there is no
interactive session — identically whether queried through the native
Keychain Services API or `security` itself, and regardless of whether the
keychain is actually locked. Only a bounded subprocess reliably recovers
from that; an in-process native call has no such backstop once it blocks
inside the syscall. Enigma reports `locked` when the underlying error says
so, and `unavailable` when the query had to be killed after timing out
without one — both mean "try again from a session that can actually
unlock this," never a silent hang. Writes use the native binding directly
(a plain in-memory call, so the secret never touches a command line), are
not verified by reading the value back afterward (the operation just
confirmed broken in headless sessions), and only happen once, at first
enrollment.

This means the macOS Keychain provider is verified for an interactive
desktop session — a logged-in human running `enigma login` and later
`enigma serve` — not for unattended automation with no session at all
(headless CI, a cron job, an SSH-only remote Mac). For that, use the file
provider explicitly.

On Windows, generic credentials are always scoped to the current user's
logon session (`CredReadW` reads "the credential set associated with the
logon session of the current token"); Enigma never sets DPAPI's
`CRYPTPROTECT_LOCAL_MACHINE` flag, which would let any local user decrypt
the key. The underlying credential-store library does not expose Windows'
`persistence` attribute, so new credentials get its own default of
Enterprise persistence — the value roams with an Azure AD/domain-joined
user profile's Windows credential roaming if an administrator has enabled
it, rather than staying pinned to Local (this machine only). Most personal
and non-domain-joined machines have credential roaming off by default. If
your environment enables it, treat the master key as roamed with your
user profile and scope down access accordingly.

The owner-only file provider is compatibility mode and requires explicit
opt-in:

```bash
export ENIGMA_MASTER_KEY_PROVIDER=file
enigma login jenkins
```

This writes `$XDG_STATE_HOME/enigma/.master` at `0600`; the provider manifest
keeps later invocations pinned to it. Existing unmarked stores are pinned
only when one candidate key decrypts every credential record; ambiguous or
corrupt state fails without rewriting credentials.

For a fresh systemd user service, pass a raw 32-byte key as an encrypted
systemd credential:

```bash
install -d -m 700 ~/.config/enigma
dd if=/dev/urandom bs=32 count=1 status=none | \
  systemd-creds --user encrypt --name=enigma-master-key - \
  ~/.config/enigma/enigma-master-key.cred
```

Add these settings to the service:

```ini
[Service]
LoadCredentialEncrypted=enigma-master-key:%h/.config/enigma/enigma-master-key.cred
Environment=ENIGMA_MASTER_KEY_PROVIDER=systemd-credential
PrivateMounts=yes
```

Do not use plaintext `SetCredential=`. Provider changes on an initialized
store are rejected; a dedicated migration command is required before moving
existing encrypted state to systemd credentials.

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
enigma login <github|gitlab|jenkins> [--as <alias>]
                                  authenticate and store credentials for a backend
enigma login jira [--site <name-or-url>] [--scope <scope>] [--as <alias>]
                                  Jira Cloud OAuth 2.0 (3LO), via JIRA_CLIENT_ID/JIRA_CLIENT_SECRET
enigma login google [--scope <scope>] [--as <alias>]
                                  Drive/Docs OAuth device flow, via GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET
enigma login oidc --name <name> --issuer <url> --client-id <id> [--scope <scope>] [--env-var <VAR_NAME>]
                                  generic OIDC device flow for any compliant provider
enigma login apikey --name <name> --env-var <VAR_NAME>
                                  generic static API key, no OAuth (Brave, Tavily, Exa, ...) --
                                  prompts with input hidden, or set ENIGMA_APIKEY_VALUE non-interactively
enigma rotate <backend>           force a refresh of a stored credential
enigma revoke <backend>           delete a stored credential
enigma show <backend>             print the real, decrypted credential -- human terminal use only
enigma list                       list backends with a stored credential
enigma health                     talk to a running instance, print status JSON
```

### Viewing a real credential value

`enigma list` and `/secrets`' [services]/[secrets] menus stay redacted by
default -- names and status only. Two places show the real value, both
going through the same authenticated `GET /creds/:backend` path and so
both covered by the same audit logging (below):

- `enigma show <backend>` -- CLI, for a human at a real terminal.
- `/secrets`' per-secret **Reveal** action -- pi's own shared secrets
  command, but refused outright outside a real interactive TUI session
  (`ctx.mode !== "tui"`): `/secrets` is one command definition shared
  across tui/rpc/print/json modes, and an RPC-driven caller could
  otherwise walk the same menu picks a human would in TUI and mechanize a
  raw read. A human actually sitting at the terminal isn't restricted --
  they already have an equivalent read via `enigma show` regardless of
  what `/secrets` does, so gating the TUI path too achieves nothing beyond
  closing the one caller that's genuinely different: a non-interactive one.

Restricting the admin-token holder from ever reading their own vault's
contents isn't a real access boundary either way -- the admin token
already permits an equivalent read via `GET /creds/:backend` directly.
This mirrors a mature secrets manager like HashiCorp Vault still letting
an operator `vault kv get` a secret: the boundary that matters is
accountability (audit logging), not pretending the value is unreachable.

### Audit logging

Every `GET /creds/:backend`, `POST /rotate/:backend`, and `POST
/revoke/:backend` is logged -- backend name, resolved identity (admin, or
a registered client's name/uid), and outcome (`ok`/`denied`/`not_found`/
`unauthenticated`) -- matching a real secrets manager's own audit-device
model. The credential value itself is never logged, only the fact and
outcome of the access.

### Multiple accounts on the same platform

`--as <alias>` stores the credential under `<alias>` instead of the
platform's literal name, so a second account never overwrites the first:

```bash
enigma login github                    # stored as "github" -> GITHUB_TOKEN
enigma login github --as github-work   # stored as "github-work" -> GITHUB_WORK_TOKEN
```

A unit's `daemons.json` `backends` list then names whichever account it
wants (`"backends": ["github-work"]`), and gets that account's token
injected under the derived prefix -- `{ALIAS}_TOKEN` for GitHub/GitLab,
`{ALIAS}_API_TOKEN`/`{ALIAS}_URL`/`{ALIAS}_USER` for Jira/Jenkins,
`{ALIAS}_ACCESS_TOKEN` for Google -- matching each platform's own var-name
convention under the literal name, just prefixed by the alias instead.
Rotation and refresh work identically for an aliased account; only the
vault key and the injected variable names change. `/secrets`' "Log in a
backend" flow offers the same optional "Save as" prompt.

Every device-flow or auth-code login (github, gitlab, google, oidc, jira)
always prints the verification URL/code, and also best-effort opens it in
your default browser (via `open` -- `open` on macOS, `start` on Windows,
`xdg-open` elsewhere). If no browser is reachable (headless session, no
display, nothing installed to open it), it says so and falls back to the
printed URL -- login itself never fails just because the browser didn't
open. Works the same way from `/secrets`' "Log in a backend" flow inside
pi.

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

### Static API keys (no OAuth) -- Brave, Tavily, Exa, Serper, SerpApi, ...

Some consumer daemons (web-spider's search providers, for example) don't
authenticate via OAuth at all -- just a bearer key issued from a dashboard,
with no expiry and nothing to refresh. `enigma login apikey` covers this the
same way `login jenkins` already covers Jenkins' own static token, but the
value is never a CLI flag: at a real terminal it's a masked prompt (input
hidden, never echoed, never on argv or in shell history); non-interactively
(scripting, provisioning) set `ENIGMA_APIKEY_VALUE` instead and the prompt
is skipped. `--env-var` says which variable name the consumer daemon
actually reads:

```bash
enigma login apikey --name brave --env-var BRAVE_SEARCH_API_KEY
Paste the "brave" API key (input hidden): 
```

The `/secrets` command inside pi opens the same registration form (name,
env var, masked value field) rather than the plain, unmasked `ctx.ui.input()`
dialog every other backend kind uses -- pi's extension API has no masked
input primitive of its own, so this is a small purpose-built TUI component
(`extension/src/apikey-form.ts`), not the built-in dialog.

No backend-specific code exists for this: `--name` is whatever the operator
chooses (matching a `daemons.json` unit's `backends` entry), and the stored
credential has no refresh capability (`resolveRefreshFn` treats it the same
as Jenkins/GitHub -- nothing to rotate).

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

## Pi extension

The `secrets` slash command manages the vault from inside [pi](https://pi.dev):
list configured backends, view redacted status (expiry/scope, never the
token), rotate, revoke, or reveal the real value -- also usable from
`/secrets`' [services] menu for any other daemon-kit consumer sharing that
command in the same session (pipes, tickets). Enabled automatically once
this package is installed as a pi extension (`pi.extensions` in
`package.json`); talks to the same running `enigma serve`/`enigma
supervisor` daemon the CLI does. `list`/`get` never return
`accessToken`/`refreshToken`/`extra` -- see
`src/secrets-backend-adapter.ts`'s explicit SecretRecord allow-list.
Reveal is the one deliberate exception, and only fires in a real
interactive TUI session (see "Viewing a real credential value" above);
RPC/print/JSON invocations of `/secrets` are refused. Login stays
CLI-only (`enigma login <backend>`); it's an interactive device-flow
prompt, not something a slash command or LLM tool call can drive.

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
		},
		{
			"name": "web-spider",
			"bin": "/path/to/web-spider-daemon/src/cli.ts",
			"args": ["serve"],
			"backends": ["brave", "tavily"],
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
