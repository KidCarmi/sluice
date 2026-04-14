# Sluice Security Model

## Architecture summary

Sluice is a **stateless content-disarm engine**. It has no concept of users,
groups, IPs, or policy. Culvert owns all of that; Sluice's only API contract
is: "here is a file, here is a profile name and mode — return sanitized bytes
and a threat report."

This document lists the security posture guarantees and the production
hardening checklist.

---

## Trust boundaries

| Caller | Transport | Auth | Scope |
|--------|-----------|------|-------|
| Culvert (remote) | gRPC mTLS on `:8443` | Client cert signed by Sluice CA | `Sanitize`, `Health` |
| Culvert (bootstrap) | gRPC on `:8443`, no client cert | One-time TOFU token | `Enroll` only |
| Local operator | Unix socket on `/data/sluice.sock` | Filesystem perms (0600, owner-only) | All RPCs |
| Developer browser | HTTPS testing UI (off by default) | Bearer token (0600 file) | `Sanitize` forced to `default` profile + `ENFORCE` mode |

**No inbound channel grants more than the RPCs it authenticates.** `Enroll`
explicitly cannot call `Sanitize` without first presenting the client cert
it was just issued.

---

## Proto contract invariants (enforced by the server)

1. `SanitizeResponse.Result` is ALWAYS the first message. Chunks follow.
   Never interleaved. (Client reads first message, branches on `Status`.)
2. `Mode=REPORT_ONLY` / `BYPASS_WITH_REPORT` → server returns
   **original bytes unchanged**, regardless of profile rules. `sanitized_sha256`
   is computed over the returned bytes (= original bytes).
3. Oversize files → `InvalidArgument` with `file_too_large:` prefix.
   (Never `ResourceExhausted`; different retry semantics.)
4. `Enroll` is the only RPC callable without a verified client cert.
   The unary + stream interceptors check `peer.AuthInfo`'s verified chain
   length on every other method.
5. `Threat.severity` is exactly one of `{low, medium, high, critical}`.
   (Culvert's alert thresholds branch on these values.)
6. `policy_version` is logged only — never used as a Prometheus label
   (cardinality explosion risk).
7. `tags` are capped at 16 keys / 64 B key / 256 B value. Only the
   allowlisted keys (`direction`, `dest_category`) become Prometheus labels.

---

## Enrollment

- Token bytes: 32 from `crypto/rand`, base64url-encoded (~43 chars plaintext).
- Stored: **SHA-256 hash only**. Plaintext lives in memory only until
  `GenerateToken` returns, and on disk in the token file (mode `0600`).
- TTL: 24h default, configurable via `enrollment.token_ttl`.
- Single-use: `Enroll` deletes the entry on success.
- TOFU: operator reads the server's SHA-256 cert fingerprint from
  `sluice token` output and pastes it into Culvert's enroll UI alongside
  the token. Culvert pins-verifies before sending the token; no plaintext
  on the wire without out-of-band fingerprint match.
- `RevokeAll()` supports emergency rotation.

---

## Testing UI defaults

The testing UI is **off by default**. When enabled, defaults are:

| Setting | Default |
|---------|---------|
| `enabled` | `false` |
| `addr` | `127.0.0.1:8080` |
| `use_tls` | `true` (reuses server cert from mTLS port) |
| `require_auth` | `true` |
| `auth_token_file` | `/data/ui_token` (mode `0600`, auto-generated on first boot) |
| `max_uploads_per_hour` | `20` per client IP |
| `max_file_size` | `10 MB` (separate from the engine's `limits.max_file_size`) |

Additional guarantees:
- Content-Security-Policy: `default-src 'self'; …` (restrictive)
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` locking down
  camera/mic/geo.
- Uploads forced to `profile=default`, `mode=ENFORCE` — the UI is NOT a
  policy-bypass oracle.
- Metrics from the UI are labelled `ui_test="true"` so they do not pollute
  production counters.
- Startup banner (stderr) + Warn-level log entry announce the UI is enabled.

---

## Production hardening checklist

Before running Sluice in production:

- [ ] Use `deploy/docker-compose.prod.yml` (not `docker-compose.yml`).
- [ ] Confirm `testing_ui.enabled: false` (prod compose also omits the
      HTTP port binding).
- [ ] Publish gRPC port on `127.0.0.1:8443` only; let Culvert reach it via
      loopback.
- [ ] Confirm `docker exec <container> sluice health` returns `healthy`.
- [ ] Pull the enrollment token with `sluice token` and register Culvert;
      verify the fingerprint in Culvert's UI matches Sluice's output.
- [ ] After enrollment, `sluice token` will show "no tokens currently
      outstanding" — the single-use token is gone.
- [ ] Monitor Prometheus for `sluice_files_processed_total` and
      `sluice_threats_removed_total` counters.
- [ ] Rotate server certs annually (`sluice cert server-rotate` — v0.2).

---

## Threat model

### In scope
- Malicious PDFs, Office docs, images, SVGs, ZIPs submitted through
  Culvert.
- A compromised Culvert node attempting to call Sluice outside its
  established mTLS channel.
- An attacker on the same LAN as the Sluice host attempting to reach the
  mTLS port without a client cert.
- An attacker probing the testing UI without a bearer token.
- Zip bombs / entity-expansion attacks / token brute-force.

### Out of scope
- Compromise of the Sluice host itself (OS-level).
- Side-channel attacks against the sanitizer's in-memory data.
- Physical tampering with the token file.
- DoS at the network layer (use iptables / AWS SG).

### Mitigations (per-sanitizer)
See `SLUICE-CDR-HANDOFF.md` for the file-type-specific threat/mitigation
matrix. Key high-level controls:
- Every sanitizer uses `io.LimitReader` on input.
- `filepath.Clean` + traversal checks on every archive entry.
- `maxDecompressedTotal` cap to stop zip bombs.
- `max_pixels` cap (100 MP) on image sanitizer.
- SVG XML decoder has `Entity` disabled (no XXE) and a token-count cap.
- Each sanitizer runs in a worker-pool goroutine with a per-job timeout
  and `recover()` — one bad file cannot take down the service.

---

## Reporting a vulnerability

See `SECURITY.md` in the repo root for the disclosure process.
