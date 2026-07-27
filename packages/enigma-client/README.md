# @danypops/enigma-client

Client for talking to a running [Enigma](https://github.com/DanyPops/enigma) vault: discovers it via its documented handle/token files, presents a token, fetches a credential. Never imports Enigma's own source — only `@danypops/daemon-kit`'s generic daemon-discovery and vault-client primitives, which any daemon already depends on for its own plumbing.

Every call is bounded (500ms) and non-throwing: "Enigma isn't running," "not configured for this backend," and "unreachable" all resolve to `undefined`, never an error. A slow or hung Enigma can never stall your own daemon's startup.

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
