# Sluice — Content Disarm & Reconstruction Engine

Works with **[Culvert](https://github.com/KidCarmi/Culvert)** — Sluice is the sanitization sidecar that Culvert's forward proxy calls over gRPC + mTLS.
Single-binary Go. Docker-native.

**Supported types (v0.1):**

| Format | Notes |
|---|---|
| PDF, DOCX, XLSX, PPTX | Macros, OLE, ActiveX, embedded files, external refs stripped |
| JPEG, PNG, GIF | Full re-encode to raw pixels (destroys EXIF, XMP, stego, ICC profiles) |
| SVG | `<script>`, event handlers, `javascript:` URIs stripped → `SANITIZED` |
| ZIP | Recursive: unpacks, sanitizes each member, repacks |

Default per-file cap is **50 MB**. Configurable via `limits.max_file_size`. Files over the cap are rejected with gRPC `InvalidArgument file_too_large:` before any processing.

**Architecture:** stateless CDR engine. No user accounts, no policy, no identity. Culvert owns all of that and tells Sluice which profile to run on each file.

---

## Quickstart: Culvert + Sluice in 3 minutes

### 1. Add Sluice to your Culvert `docker-compose.yml`

```yaml
services:
  sluice:
    image: ghcr.io/kidcarmi/sluice:latest
    container_name: culvert-sluice
    user: "65532:65532"
    restart: unless-stopped
    ports:
      - "127.0.0.1:8443:8443"   # mTLS gRPC (localhost only)
      - "127.0.0.1:9190:9090"   # Prometheus
    volumes:
      - sluice-data:/data

volumes:
  sluice-data:
```

### 2. Start Sluice

```bash
docker compose up -d sluice
```

### 3. Get the enrollment token + fingerprint

```bash
docker exec culvert-sluice sluice token
```

Output:

```
SLUICE_ENROLL_TOKEN=eyJhbGci...
SLUICE_SERVER_FINGERPRINT=sha256:a1b2c3...
Expires: 2026-04-15T14:22:01Z (24h)
```

> **TOFU footgun:** the fingerprint authenticates the server on first contact.
> Move it to Culvert over a **trusted channel** — the same `docker exec`/SSH
> session is fine; a public chat or paste bin is not. A MITM with the token
> but not the real fingerprint cannot complete enrollment.

### 4. Register in Culvert

Culvert admin UI → **Integrations → CDR → Add Sluice Instance**. Four fields:

1. **Name** (your label for this instance, e.g. `sluice-us-east-01`)
2. **Endpoint** (e.g. `127.0.0.1:8443`)
3. **Enrollment token** (from step 3)
4. **Server fingerprint** (from step 3)

Click **Enroll**. Culvert TOFU-verifies the fingerprint against the server's TLS handshake, then swaps to CA-based mTLS. The token is consumed immediately on success and cannot be reused.

### 5. Verify & manage

```bash
docker exec culvert-sluice sluice health          # liveness + stats
docker exec culvert-sluice sluice fingerprint     # server cert SHA-256
docker exec culvert-sluice sluice token rotate    # emergency: revoke all pending tokens + issue fresh
```

---

## Deployment modes

Two compose files ship under `deploy/`:

| File | Purpose | Testing UI |
|------|---------|------------|
| `deploy/docker-compose.yml` | Production (default) | Disabled, mTLS-only |
| `deploy/docker-compose.dev.yml` | Developer laptop | Enabled (HTTPS + bearer auth) |

Use the default unless you are actively debugging. Dev overlay:

```bash
docker compose -f deploy/docker-compose.dev.yml up --build
```

---

## Management surface

Sluice has **no admin web UI, no user accounts, no RBAC** — by design. All operator interaction is via `docker exec`:

| Command | Purpose |
|---------|---------|
| `sluice token` | Print current enrollment token + server fingerprint |
| `sluice token rotate` | Revoke all pending enrollment tokens, issue a new one (does NOT revoke already-enrolled client certs — use `sluice cert ca-rotate` or `sluice node revoke` for that) |
| `sluice fingerprint` | Print the server cert SHA-256 fingerprint |
| `sluice health` | Local health check (exit 0 / non-zero) |
| `sluice version` | Print version + build info |
| `sluice node list [--all] [--json]` | List enrolled clients with expiry + status |
| `sluice node show <fingerprint>` | JSON dump of one client's ledger record |
| `sluice node revoke [--reason ...] <fingerprint>` | Revoke a single client (sync; takes effect on next RPC) |
| `sluice node revoke-all --yes` | Revoke every active client (does NOT rotate the CA — use for a wide sweep without forcing re-enrollment via a new CA) |
| `sluice cert server-rotate [--grace 24h]` | Rotate the server cert; previous fingerprint is advertised via Health during the grace window for zero-downtime Culvert re-pinning |
| `sluice cert ca-rotate --yes` | Regenerate the CA (INVALIDATES ALL CLIENT CERTS). Operators must re-enroll every Culvert node afterward. |
| `sluice cert expiry` | Print current server cert CN + fingerprint |

See `docs/cli-reference.md` for the full surface and exit codes. Culvert's admin UI reaches the same handlers over mTLS gRPC.

---

## Certificate lifetime

| Cert | Lifetime | Renewal path |
|---|---|---|
| CA | 10 years | `sluice cert ca-rotate` — forces re-enrollment of every Culvert node. Use only if the CA key is suspected compromised. |
| Server cert | 1 year | `sluice cert server-rotate [--grace 24h]` — mints a fresh server cert signed by the existing CA. During the grace window `HealthResponse.rotated_fingerprint` lets Culvert accept the OLD fingerprint so clients can auto-rewrite their pin without re-enrollment. |
| Client cert (via `Enroll` or `RenewCert`) | 1 year | Culvert's auto-renewal calls `RenewCert(empty)` over the existing mTLS channel once its cert is < 30 days from expiry. Old cert keeps working until its own `NotAfter` — `RenewCert` does NOT revoke it (would break in-flight streams). Explicit revocation is available via `RevokeClient(fingerprint)` or `sluice node revoke <fp>`. |

The CLI banner `Expires:` timestamp applies to the **enrollment token**, not to certs. Token TTL defaults to 24h, configurable via `enrollment.token_ttl`.

### v0.2 RPCs

In addition to v0.1's `Sanitize`, `Health`, `Enroll`:

- **`RenewCert`** (unary, mTLS-required) — mints a fresh client cert for the caller (same CN as the presented cert). Response includes `days_until_expiry` so pollers don't re-parse the cert.
- **`RevokeClient`** (unary, mTLS-required) — synchronous revocation by SHA-256 fingerprint. Revoked clients' subsequent RPCs fail with `PermissionDenied`. Self-revocation is refused (`InvalidArgument`).
- **`HealthResponse.server_fingerprint` + `rotated_fingerprint` + `rotated_fingerprint_until_unix`** — dual-pin rotation metadata. Empty/zero when no rotation is active.

---

## Documentation

- **`docs/cli-reference.md`** — every subcommand, flag, and exit code
- **`docs/operations.md`** — day-2 runbook (cert rotation, draining, updates)
- **`docs/security.md`** — threat model, hardening checklist, testing-UI defaults
- **`SLUICE-CDR-HANDOFF.md`** — the original design spec

---

## Contract with Culvert

The gRPC contract lives in `proto/sluicev1/sluice.proto`. Three RPCs:

- **`Sanitize`** (bidi stream) — client sends `SanitizeHeader` then chunks, server responds with `SanitizeResult` (atomic, first message) then chunks.
- **`Health`** (unary) — reports worker stats + supported profiles.
- **`Enroll`** (unary) — exchanges a one-time TOFU-verified token for mTLS certs.

Key contract details:
- `SanitizeResponse.Result` is **always** the first message; chunks follow. Never interleaved.
- `Mode=REPORT_ONLY` and `Mode=BYPASS_WITH_REPORT` **guarantee** the server returns original bytes unchanged, regardless of what the profile would do.
- Oversize files → gRPC `InvalidArgument` with `file_too_large:` prefix. (Never `ResourceExhausted` — different retry semantics for circuit breakers.)
- Unknown `profile_name` → `Status=ERROR` with `error_message="unknown_profile: <name>"`.
- Empty `profile_name` ≡ `"default"`.
- `HealthResponse.profiles[i].max_file_size_bytes` is the **authoritative per-profile cap**. Clients should read it from Health and enforce `min(clientCap, profileCap)` client-side so oversize files never hit the wire.

---

## Build

```bash
make tools        # install protoc + plugins
make proto        # regenerate .pb.go
make test         # race-detector tests
make bench        # sanitizer benchmarks
make build        # produce ./sluice binary
```

---

## License

MIT. See `LICENSE`.
