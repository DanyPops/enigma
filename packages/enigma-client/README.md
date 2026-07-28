# @danypops/enigma-client

Client for talking to a running [Enigma](https://github.com/DanyPops/enigma) vault: discovers it via its documented handle/token files, presents a token, fetches a credential. Never imports Enigma's own source — only `@danypops/daemon-kit`'s generic daemon-discovery primitives, which any daemon already depends on for its own plumbing. Enigma's own wire protocol (`GET /creds/:backend`, `GET /whoami`) is implemented directly in this package.

Every call is bounded (500ms) and non-throwing: "Enigma isn't running," "not configured for this backend," and "unreachable" all resolve to `undefined`, never an error. A slow or hung Enigma can never stall your own daemon's startup.

## Transport

Prefers a Unix-socket connection to Enigma's admin socket (kernel-verified peer identity via `SO_PEERCRED`, no bearer credential needed at all) whenever one is present, falling back to TCP + bearer token otherwise -- an older Enigma with no Unix-socket support, or none running, look identical from here. Nothing about a caller's own code changes either way: `tryEnigmaCredential`/`tryEnigmaAccessToken`/`tryEnigmaWhoAmI` behave the same regardless of which transport actually served the request. Passing your own `fetchImpl` (below, or in a test) always pins the TCP path explicitly and skips Unix-socket detection entirely.

## Usage

```ts
import { tryEnigmaCredential, tryEnigmaAccessToken } from "@danypops/enigma-client";

// Full credential (accessToken + extra fields like url/username, e.g. Jenkins)
const credential = await tryEnigmaCredential("jenkins");
if (credential) {
  const { accessToken, extra } = credential;
}

// Just the bare access token, when you resolve url/etc. separately
const token = await tryEnigmaAccessToken("github");
```

### Using your own registered token

If you've registered your service with Enigma (`enigma client add <name> --backends <list>`), pass your own token instead of relying on Enigma's shared admin-token file:

```ts
const credential = await tryEnigmaCredential("jira", { token: myRegisteredToken });
```

### Discovering your own scope instead of hardcoding backend names

`tryEnigmaWhoAmI` returns the calling token's own registration -- name and backend list -- straight from Enigma, so a consumer never has to guess or hardcode the exact backend name an operator chose at `enigma login`:

```ts
import { tryEnigmaWhoAmI, tryEnigmaCredential } from "@danypops/enigma-client";

const who = await tryEnigmaWhoAmI({ token: myRegisteredToken });
for (const backend of who?.backends ?? []) {
  const credential = await tryEnigmaCredential(backend, { token: myRegisteredToken });
  // credential.extra.envVarName is the env var the operator chose at login time
  if (credential?.extra?.envVarName) {
    process.env[credential.extra.envVarName] = credential.accessToken;
  }
}
```
