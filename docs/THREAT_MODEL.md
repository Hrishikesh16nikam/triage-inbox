# Threat model

Triage Inbox handles messages that, in a real deployment, would contain health information. This document covers what it protects, from whom, how, and what it does not handle yet. The demo uses synthetic data only.

## Assets

| Asset | Why it matters |
|---|---|
| Message content (transcripts, documents) | Health information about real people in a real deployment |
| Identifiers inside messages (phone, DOB, IDs) | Make the content traceable to a person |
| Accounts and sessions | Grant access to everything above |
| The audit log | The record of who accessed and changed what; must be trustworthy after an incident |
| The secret key | Signs access tokens and the audit chain |

## Actors

1. **Outside attacker** on the network, with no account.
2. **Malicious or curious insider** with a valid low-privilege account (viewer or triager).
3. **Attacker with a stolen token** (for example via an XSS bug or a compromised laptop).
4. **Attacker with database file access** (stolen backup, misconfigured volume) but not the secret key.
5. **Malicious content**: an uploaded message crafted to attack the pipeline or the model.

## Trust boundaries

```
browser ──HTTPS──▶ HTTP layer ──▶ services ──▶ SQLite + upload dir
                                     │
                                     └──▶ transcriber / classifier (local, optional model)
```

Everything from the browser is untrusted, and so is everything inside an uploaded file, including text a model will read.

## STRIDE

| Threat | Example | Mitigation |
|---|---|---|
| **Spoofing** | Password guessing | scrypt hashing; per-IP login rate limit (5/min); identical error and timing for unknown users and wrong passwords |
| | Forged access token | HS256 with a derived key; header must be exactly `{"alg":"HS256","typ":"JWT"}`, so `alg: none` and algorithm confusion are rejected |
| | Stolen refresh token | Refresh tokens are single-use and rotate; replaying a used one revokes the whole session family and is audited |
| **Tampering** | Edit an item through the API | Only `triage_state` and `assigned_to` are writable; server-side validation and role checks |
| | Rewrite the audit log in the database | Append-only triggers, plus an HMAC chain: editing, reordering or deleting an entry breaks verification, and forging a new chain needs the key |
| | Upload disguised as another type | Extension allowlist plus content sniffing; files stored under random IDs, never user-supplied names |
| **Repudiation** | "I never looked at that message" | Logins, uploads, processing, updates and every read of message content are audited in the same transaction as the action |
| **Information disclosure** | Raw identifiers leaking through the UI, logs or a model | Redaction runs before anything is stored or classified; the raw text and the raw upload are discarded after processing (configurable) |
| | Session theft through XSS | Access token in memory only; refresh token in an `HttpOnly`, `SameSite=Strict` cookie scoped to `/api/auth`; strict CSP with no inline script; UI renders text with `textContent` only |
| | CSRF using the refresh cookie | `SameSite=Strict`, plus an `Origin` check on cookie-authenticated endpoints; all other endpoints need a bearer token |
| | Error messages exposing internals | Unhandled errors return a generic 500; details go to the server log only |
| | Clickjacking, MIME sniffing, referrer leaks | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `Referrer-Policy: no-referrer`, `no-store` on API responses |
| **Denial of service** | Huge uploads, flooding | Body size limits enforced before reading, chunked bodies refused, upload and refresh rate limits |
| | Poison file crashing the worker | Each item is retried at most 3 times, then marked failed; the worker survives any single item |
| **Elevation of privilege** | Viewer calling triager endpoints | Role checked per route; the user's role and active flag are re-read from the database on every request, so demotion or deactivation is immediate |
| | Prompt injection in a message ("ignore your instructions...") | The model only labels already-redacted text; its output must match fixed label sets or it is discarded in favor of the rule-based result |

## Known gaps and residual risks

- **Audit log truncation.** Deleting the newest entries leaves a shorter chain that still verifies. Fix: periodically publish the chain head (`verify-audit` prints it) to an external, append-only location and compare.
- **Redaction misses.** Pattern matching doesn't catch names, identifiers spelled out in words ("five five five...") or unusual formats. A production system would add a named-entity model and treat redaction as one layer, not a guarantee.
- **No encryption at rest.** SQLite and uploads are plain files. Use full-disk or volume encryption, or SQLCipher.
- **HTTPS is not built in.** Run behind a TLS-terminating reverse proxy and set `TRIAGE_SECURE_COOKIES=1` (adds `Secure` cookies and HSTS). Use `--trust-proxy` only when a proxy you control sets `X-Forwarded-For`, otherwise clients can spoof their IP for rate limiting.
- **Per-process rate limits.** Limits live in memory, so several replicas would each allow the full rate. A shared store such as Redis fixes this.
- **Single shared secret.** One key signs tokens and the audit chain (through separate derived subkeys). Rotating it invalidates sessions and requires re-anchoring the audit chain.
- **No MFA or account lockout.** Rate limiting slows guessing but does not stop a slow distributed attack.
- **Hand-written JWT handling and a standard-library HTTP server.** Chosen to keep the project dependency-free and readable. A production service should prefer vetted libraries and a hardened server.
