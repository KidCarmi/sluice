# Sluice — Content Disarm & Reconstruction Engine

**Sluice is not a Culvert sidecar** — it's an independent CDR service that
Culvert (or any future client implementing the proto) talks to over gRPC +
mTLS. Run it wherever your security posture requires: next to the proxy, on a
dedicated VM, or as a shared Kubernetes service for a whole team.

Stateless. Horizontally scalable. Single Go binary, Docker-native.

**Supported types (v0.2):**

| Format | Notes |
|---|---|
| PDF, DOCX, XLSX, PPTX | Macros, OLE, ActiveX, embedded files, external refs stripped |
| JPEG, PNG, GIF | Full re-encode to raw pixels (destroys EXIF, XMP, stego, ICC profiles) |
| SVG | `<script>`, event handlers, `javascript:` URIs stripped → `SANITIZED` |
| ZIP | Recursive: unpacks, sanitizes each member, repacks |

Default per-file cap is **50 MB**. Configurable via `limits.max_file_size`. Files over the cap are rejected with gRPC `InvalidArgument file_too_large:` before any processing.

**Architecture:** stateless CDR engine. No user accounts, no policy, no identity. Culvert owns all of that and tells Sluice which profile to run on each file. One Sluice can serve many Culvert nodes; scale horizontally by adding more Sluice instances and enrolling each Culvert against all of them.

---

## Deployment topologies

Pick the shape that matches your operation:

### 1. Co-located (demo / single-host)

Sluice in the same `docker-compose.yml` as Culvert. gRPC bound to `127.0.0.1:8443` — no other host can reach it. Simplest to reason about; good for laptops, single-VM installs, and CI.

Config: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) → use this as a block inside your Culvert compose.

### 2. Standalone service (team / staging)

Sluice on its own host or its own compose, listening on `0.0.0.0:8443`. One Sluice serves N Culvert nodes over the network. Decouples Sluice upgrades from Culvert upgrades; operationally simpler when multiple Culvert fleets share the same sanitization pool.

Config: [`deploy/docker-compose.standalone.yml`](deploy/docker-compose.standalone.yml).

```bash
docker compose -f deploy/docker-compose.standalone.yml up -d
```

### 3. Dedicated fleet (production / HA)

Multiple Sluice instances behind a DNS name or load balancer. Culvert's client pool round-robins across them. No clustering — each Sluice is independent. To add capacity or an HA replica, just start another instance and enroll it.

Kubernetes: deploy the image as a `Deployment` with `replicas: N` plus a `ClusterIP` Service (or `LoadBalancer` / Ingress with TLS passthrough for cross-cluster callers).

### Cross-host networking checklist

When Sluice and Culvert run on different hosts:

1. **Bind** gRPC to `0.0.0.0:8443` (use `standalone.yml`), not `127.0.0.1`.
2. **Firewall** 8443/tcp so only trusted Culvert subnets can reach it. mTLS handles auth, but not anti-DoS.
3. **Stable DNS** — give Sluice a name like `sluice.internal.corp` so Culvert's endpoint config survives IP churn.
4. **Prometheus** — `:9090` must be reachable from your scrape target. In Kubernetes, publish it on the pod network, not loopback.
5. **TLS passthrough** — if you front Sluice with a load balancer or Ingress, use TCP / TLS-passthrough mode. **Do not terminate TLS at the LB** — the mTLS handshake must reach Sluice directly or the client cert is lost.

### Scaling guidance

One Sluice instance can enroll and serve an unlimited number of Culvert nodes — each gets its own client cert. Concurrency is bounded by `workers.max_concurrent` (default 10) with a queue depth of 50. Throughput is bound by the underlying CPU/RAM budget.

Starting point for capacity planning: **~10 Culvert nodes per Sluice vCPU**. Watch `sluice_queue_depth` in Prometheus; sustained non-zero queue depth means you're bottlenecked — add a Sluice instance and enroll each Culvert against both.

There is no clustering. Sluice instances don't talk to each other. Each maintains its own CA and issues its own client certs. For an HA deploy, you either:
- **Distribute a single CA** via your secret manager (Vault, sealed-secrets, etc.) so every Sluice issues certs from the same root, and Culvert trusts all of them identically.
- **Let each Sluice have its own CA** and enroll each Culvert against each Sluice separately. More tokens to manage; trivial to reason about trust boundaries.

---

## Quickstart: Culvert + Sluice in 3 minutes (co-located)

### 1. Add Sluice to your Culvert `docker-compose.yml`

```yaml
services:
  sluice:
    image: ghcr.io/kidcarmi/sluice:latest
    container_name: culvert-sluice
    user: "65532:65532"
    restart: unless-stopped
    ports:
      - "127.0.0.1:8443:8443"   # mTLS gRPC (localhost only — same host)
      - "127.0.0.1:9190:9090"   # Prometheus
    volumes:
      - sluice-data:/data

volumes:
  sluice-data:
```

For cross-host: use [`deploy/docker-compose.standalone.yml`](deploy/docker-compose.standalone.yml) instead, bind `0.0.0.0:8443`, and firewall appropriately.

### 2. Start Sluice

```bash
docker compose up -d sluice
```

### 3. Get the enrollment token + fingerprint

On the Sluice host:

```bash
docker exec culvert-sluice sluice token
```

Output:

```
SLUICE_ENROLL_TOKEN=eyJhbGci...
SLUICE_SERVER_FINGERPRINT=sha256:a1b2c3...
Expires: 2026-04-15T14:22:01Z (24h)
```

> **TOFU integrity — read this even if you think you know it:**
> The fingerprint authenticates the server on first contact. Move it to
> whoever's running Culvert admin over a **trusted channel**:
> - Same `docker exec`/SSH session as the person clicking buttons in Culvert ✅
> - Internal chat with E2E encryption between known parties ✅
> - Public paste bin, bug tracker, Slack channel with 500 people, email ❌
>
> A MITM with the token but not the real fingerprint cannot complete
> enrollment — but they can complete it if you leak the fingerprint.

### 4. Register in Culvert

Culvert admin UI → **Integrations → CDR → Add Sluice Instance**. Four fields:

1. **Name** (your label, e.g. `sluice-us-east-01`)
2. **Endpoint** (`127.0.0.1:8443` for co-located, `sluice.internal.corp:8443` for standalone)
3. **Enrollment token**
4. **Server fingerprint**

Click **Enroll**. Culvert TOFU-verifies the fingerprint against the server's TLS handshake, then swaps to CA-based mTLS. The token is consumed immediately on success.

### 5. Verify & manage

```bash
docker exec culvert-sluice sluice health           # liveness + stats
docker exec culvert-sluice sluice fingerprint      # server cert SHA-256
docker exec culvert-sluice sluice node list        # enrolled clients
docker exec culvert-sluice sluice token rotate     # emergency: revoke pending tokens + issue fresh
```

---

## Deployment mode summary

| File | Use when | gRPC bind |
|------|----------|-----------|
| [`deploy/docker-compose.yml`](deploy/docker-compose.yml) | Co-located with Culvert on the same host | `127.0.0.1:8443` |
| [`deploy/docker-compose.standalone.yml`](deploy/docker-compose.standalone.yml) | Shared CDR service for a team or fleet | `0.0.0.0:8443` (firewall!) |
| [`deploy/docker-compose.dev.yml`](deploy/docker-compose.dev.yml) | Developer laptop / debugging | `0.0.0.0:8443` + testing UI |

Use the default co-located compose for demos and single-host installs. Switch to standalone the moment you have more than one Culvert.

---

## Backup & disaster recovery

What lives in the `sluice-data` volume (`/data` inside the container):

| Path | Back up? | On loss |
|---|---|---|
| `/data/ca.pem`, `/data/ca-key.pem` | **Mandatory.** | Every Culvert must re-enroll from scratch against a fresh CA. |
| `/data/server.pem`, `/data/server-key.pem` | Nice to have. | `BootstrapServerCerts` mints a fresh server cert on restart, signed by the existing CA. Fingerprint changes — use `sluice cert server-rotate --grace 24h` to avoid forcing Culvert re-enrollment. |
| `/data/clients.json` | Recommended. | Revocation history is lost; enrolled clients still work (their certs are valid against the CA), but you can no longer list/revoke them until they come through RenewCert. |
| `/data/enrollment_token` | Safe to discard. | Regenerate with `sluice token rotate`. |
| `/data/ui_token` | Safe to discard. | Auto-regenerated on next daemon start; bookmark the new token from the logs. |
| `/data/sluice.sock` | N/A — runtime artifact. | Regenerated on daemon start. |

**Minimum backup set:** `ca.pem`, `ca-key.pem`, `clients.json`. All three are plain files; treat the CA key with the same care as any other signing key (vault, hardware HSM if you're fancy, owner-only filesystem ACLs at the bare minimum).

---

## Management surface

Sluice has **no admin web UI, no user accounts, no RBAC** — by design. All operator interaction is via `docker exec` locally or over the mTLS gRPC API remotely (Culvert admin UI uses the same RPCs):

| Command | Purpose |
|---------|---------|
| `sluice token` | Print current enrollment token + server fingerprint |
| `sluice token rotate` | Revoke pending enrollment tokens, issue a new one (does NOT revoke client certs) |
| `sluice fingerprint` | Print the server cert SHA-256 fingerprint |
| `sluice health` | Local health check (exit 0 / non-zero) |
| `sluice version` | Print version + build info |
| `sluice node list [--all] [--json]` | List enrolled clients with expiry + status |
| `sluice node show <fingerprint>` | JSON dump of one client's ledger record |
| `sluice node revoke [--reason ...] <fp>` | Revoke a single client (sync; takes effect on next RPC) |
| `sluice node revoke-all --yes` | Revoke every active client (no CA rotation) |
| `sluice cert server-rotate [--grace 24h]` | Rotate the server cert; previous fingerprint advertised via Health during grace |
| `sluice cert ca-rotate --yes` | Regenerate the CA — INVALIDATES ALL CLIENT CERTS |
| `sluice cert expiry` | Print current server cert CN + fingerprint |

See [`docs/cli-reference.md`](docs/cli-reference.md) for flags, JSON schemas, and exit codes.

---

## Certificate lifetime

| Cert | Lifetime | Renewal path |
|---|---|---|
| CA | 10 years | `sluice cert ca-rotate` — forces re-enrollment of every Culvert node. Use only if CA key is suspected compromised. |
| Server cert | 1 year | `sluice cert server-rotate [--grace 24h]` — mints fresh cert signed by existing CA. During grace window `HealthResponse.rotated_fingerprint` lets Culvert accept the OLD fingerprint so clients can auto-rewrite their pin without re-enrollment. |
| Client cert (via `Enroll` or `RenewCert`) | 1 year | Culvert's auto-renewal calls `RenewCert(empty)` over the existing mTLS channel once its cert is < 30 days from expiry. Old cert keeps working until its own `NotAfter` — `RenewCert` does NOT revoke it (would break in-flight streams). Explicit revocation via `RevokeClient(fingerprint)` or `sluice node revoke`. |

The CLI banner `Expires:` timestamp applies to the **enrollment token**, not to certs. Token TTL defaults to 24h, configurable via `enrollment.token_ttl`.

### v0.2 RPCs

In addition to v0.1's `Sanitize`, `Health`, `Enroll`:

- **`RenewCert`** (unary, mTLS-required) — mints a fresh client cert for the caller (same CN as the presented cert). Response includes `days_until_expiry`.
- **`RevokeClient`** (unary, mTLS-required) — synchronous revocation by SHA-256 fingerprint. Self-revocation refused (`InvalidArgument`).
- **`HealthResponse.server_fingerprint` + `rotated_fingerprint` + `rotated_fingerprint_until_unix`** — dual-pin rotation metadata. Empty/zero when no rotation is active.

---

## Documentation

- **`docs/cli-reference.md`** — every subcommand, flag, and exit code
- **`docs/operations.md`** — day-2 runbook (cert rotation, draining, backups, upgrades)
- **`docs/security.md`** — threat model, hardening checklist, testing-UI defaults
- **`SLUICE-CDR-HANDOFF.md`** — the original design spec

---

## Contract with Culvert

The gRPC contract lives in `proto/sluicev1/sluice.proto`. Six RPCs (v0.2):

| RPC | Kind | Auth |
|---|---|---|
| `Sanitize` | bidi stream | mTLS |
| `Health` | unary | mTLS |
| `Enroll` | unary | TOFU token (no client cert) |
| `RenewCert` | unary | mTLS |
| `RevokeClient` | unary | mTLS |

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
