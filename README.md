# garmin-connect (Rust)

Port of [`cyberjunky/python-garminconnect`](https://github.com/cyberjunky/python-garminconnect)'s
`garminconnect/client.py` to Rust, with browser TLS/JA3/JA4 impersonation via
[`wreq`](https://github.com/0x676e67/wreq) (a maintained hard-fork of
`reqwest`) — the closest Rust equivalent to Python's `curl_cffi`.

## What's ported vs. not

| Python strategy | Ported? | Notes |
|---|---|---|
| `mobile+cffi` (iOS + TLS rotation) | ✅ | `mobile+impersonated`, rotates `MOBILE_IMPERSONATIONS` |
| `mobile+requests` (plain) | ✅ | `mobile+plain` |
| `widget+cffi` (SSO embed HTML scrape) | ❌ | Deliberately skipped — see below |
| `portal+cffi` (desktop + TLS rotation) | ✅ | `portal+impersonated`, includes the 10–20s anti-WAF delay |
| `portal+requests` (plain) | ✅ | `portal+plain` |
| DI OAuth2 token exchange | ✅ | Tries all `DI_CLIENT_IDS` in order |
| JWT_WEB cookie fallback | ✅ | Reads the cookie from an explicit `Jar` (needed since `reqwest`/`wreq`'s built-in cookie store isn't readable) |
| MFA | ✅ (as a resumable `MfaContext`) | Single verify endpoint per flow; Python's dual-endpoint MFA fallback (trying both `/portal` and `/mobile` verify URLs) is not ported — add if you hit it |
| Token persistence (0600/0700) | ✅ | `dump`/`load`/`dumps`/`loads` |
| `verify_login` (probe token against API tier) | ✅ | |
| `connectapi`/`get`/`post`/`put`/`delete`/`download` with 401-retry | ✅ | |

**Why the widget strategy isn't ported:** it exists in the Python client
mainly as a `clientId`-based rate-limit bypass, achieved by scraping an HTML
login form with regex (no JS execution) and can't reliably confirm that an
email/SMS MFA code was actually sent — Python shelves that uncertainty with
some fairly involved bookkeeping (`shelved_mfa`). It's a good candidate to
add later if the four remaining strategies get rate-limited too often, but
it roughly doubles the login-chain complexity for a corner case, so I left
it out of this first pass. Happy to add it if you hit that wall.

## Usage

```rust
use garmin_connect::{GarminClient, LoginOutcome};

let mut client = GarminClient::new("garmin.com")?; // or "garmin.cn"
match client.login(email, password).await? {
    LoginOutcome::Success => {}
    LoginOutcome::NeedsMfa(ctx) => {
        let code = /* prompt the user */;
        client.resume_login(ctx, &code).await?;
    }
}
client.dump("./tokens.json")?; // persist for next run

let profile = client.get("/userprofile-service/socialProfile").await?;
```

See `examples/login.rs` for a full runnable example
(`GARMIN_EMAIL=... GARMIN_PASSWORD=... cargo run --example login`).

## Layout

- `src/native.rs` — constants + header builders (client IDs, user agents, DI auth constants)
- `src/error.rs` — `GarminError` mirroring `garminconnect.exceptions`
- `src/client.rs` — `GarminClient`: login chain, DI token exchange, generic request surface
- `src/lib.rs` — public re-exports
