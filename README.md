# Sluice — Content Disarm & Reconstruction Engine

Single-binary Go CDR service. gRPC + mTLS. Docker-native. Designed as the
sanitization sidecar for the [Culvert](https://github.com/KidCarmi/Culvert)
forward proxy.

**Supported types (v0.1):** PDF, DOCX, XLSX, PPTX, JPEG, PNG, GIF, SVG, ZIP.

**Architecture:** stateless CDR engine. No user accounts, no policy,
no identity. Culvert owns all of that and tells Sluice which profile to run
on each file.

---

## Quickstart: Culvert + Sluice in 3 minutes

### 1. Add Sluice to your Culvert `docker-compose.yml`

```yaml
services:
  sluice:
    image: ghcr.io/kidcarmi/sluice:latest
    container_name: culvert-sluice
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
Expires: 2026-04-15T14:22:01Z
```

### 4. Register in Culvert

Culvert admin UI → Integrations → CDR → Add Sluice Instance.
Paste **endpoint** + **token** + **fingerprint** (three fields).
Click Enroll. Culvert TOFU-verifies the fingerprint, then swaps to CA-based mTLS.

### 5. Verify

```bash
docker exec culvert-sluice sluice health
```

---

## Deployment modes

Two compose files ship under `deploy/`:

| File | Purpose | Testing UI |
|------|---------|------------|
| `deploy/docker-compose.yml` | Developer laptop | Enabled (HTTPS + bearer auth) |
| `deploy/docker-compose.prod.yml` | Production | Disabled, mTLS-only |

Use prod unless you are actively debugging.

---

## Management surface

Sluice has **no admin web UI, no user accounts, no RBAC** — by design.
All operator interaction is via `docker exec`:

| Command | Purpose |
|---------|---------|
| `sluice token` | Print current enrollment token + server fingerprint |
| `sluice token rotate` | Revoke all tokens, issue a new one |
| `sluice fingerprint` | Print the server cert SHA-256 fingerprint |
| `sluice health` | Local health check (exit 0 / non-zero) |
| `sluice version` | Print version + build info |

See `docs/cli-reference.md` for the full surface and exit codes.
Culvert's admin UI reaches the same handlers over mTLS gRPC.

---

## Documentation

- **`docs/cli-reference.md`** — every subcommand, flag, and exit code
- **`docs/operations.md`** — day-2 runbook (cert rotation, draining, updates)
- **`docs/security.md`** — threat model, hardening checklist, testing-UI defaults
- **`SLUICE-CDR-HANDOFF.md`** — the original design spec

---

## Contract with Culvert

The gRPC contract lives in `proto/sluicev1/sluice.proto`. Three RPCs:

- **`Sanitize`** (bidi stream) — client sends `SanitizeHeader` then chunks,
  server responds with `SanitizeResult` (atomic, first message) then chunks.
- **`Health`** (unary) — reports worker stats + supported profiles.
- **`Enroll`** (unary) — exchanges a one-time TOFU-verified token for mTLS certs.

Key contract details:
- `SanitizeResponse.Result` is **always** the first message; chunks follow.
  Never interleaved.
- `Mode=REPORT_ONLY` and `Mode=BYPASS_WITH_REPORT` **guarantee** the server
  returns original bytes unchanged, regardless of what the profile would do.
- Oversize files → gRPC `InvalidArgument` with `file_too_large:` prefix.
  (Never `ResourceExhausted` — different retry semantics for circuit breakers.)
- Unknown `profile_name` → `Status=ERROR` with `error_message="unknown_profile: <name>"`.
- Empty `profile_name` ≡ `"default"`.

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
