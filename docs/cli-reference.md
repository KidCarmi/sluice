# Sluice CLI Reference

All commands are invoked as `sluice <subcommand>`. Inside the official Docker
image, use `docker exec culvert-sluice sluice <subcommand>`.

Exit codes: `0` = success, `1` = operational error (bad config, RPC failed,
unhealthy). Where applicable, machine-readable output to stdout is
separated from human-friendly messages on stderr.

---

## `sluice`

Runs the daemon. Starts:
- mTLS gRPC server on `server.grpc_addr`
- CLI unix socket on `cli.socket_path` (same handlers; file-perm gated)
- Optional testing UI on `testing_ui.addr` (if `testing_ui.enabled = true`)

Flags:
- `--config <path>` — path to `config.yaml` (default `config.yaml`)
- `--health` — one-shot liveness check (prints `healthy`, exits 0)

---

## `sluice token [rotate]`

Prints a fresh enrollment token along with the server cert SHA-256
fingerprint and expiry. Writes the token to `enrollment.token_file`
(default `/data/enrollment_token`, mode `0600`).

Output (stdout):
```
SLUICE_ENROLL_TOKEN=eyJhbGci...
SLUICE_SERVER_FINGERPRINT=sha256:a1b2c3...
Expires: 2026-04-15T14:22:01Z
```

`rotate` revokes any previously-issued tokens. Default TTL is 24h,
configurable via `enrollment.token_ttl` in config.yaml.

Exit codes: `0` success; `1` cert bootstrap failed, token write failed,
or random source unavailable.

---

## `sluice fingerprint`

Prints the server cert SHA-256 fingerprint (no other metadata). Useful for
TOFU verification in scripts.

Output (stdout):
```
sha256:a1b2c3d4e5f6...
```

---

## `sluice health`

Connects to the local CLI unix socket and calls the `Health` RPC. Exits
`0` if the daemon reports `healthy=true`; `1` otherwise.

Output (stdout):
```
healthy version=0.1.0 active=0 queue=0
```

Used by Docker's `HEALTHCHECK`:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD /sluice health
```

---

## `sluice version`

Prints the binary version.

---

---

## `sluice node list [--all] [--json]`

Lists enrolled clients from the ledger at `/data/clients.json`.

Flags:
- `--all` — include revoked and expired records (default: active only)
- `--json` — emit raw JSON records instead of a table

Output (table):
```
FINGERPRINT                                                               ISSUED                  EXPIRES IN    STATUS
sha256:a1b2c3...                                                          2026-04-14T22:30Z       8760h0m0s     active
```

---

## `sluice node show <fingerprint>`

Prints the JSON ledger record for one client. Exit `1` if not found.

---

## `sluice node revoke [--reason ...] <fingerprint>`

Synchronously revokes one client cert. If the daemon is running the
revocation is applied over the unix socket (in-memory + on-disk atomic);
if not, the ledger file is written directly and the daemon picks it up on
next boot.

---

## `sluice node revoke-all --yes [--reason ...]`

Revokes every active client. Does NOT rotate the CA — use when you want to
force every Culvert node to re-enroll without minting a fresh CA. Requires
`--yes` to guard against typos.

---

## `sluice cert server-rotate [--grace 24h]`

Swaps the server cert for a fresh one signed by the existing CA.

`--grace` controls how long the PREVIOUS server-cert fingerprint is
advertised in `HealthResponse.rotated_fingerprint` so Culvert can continue
to accept connections after its pin was for the old cert. Default 24h.

Prints old and new fingerprints plus the next steps. Restart the daemon
after running this command (it reads certs from disk at startup).

---

## `sluice cert ca-rotate --yes`

Regenerates the CA. INVALIDATES EVERY CLIENT CERT — all Culvert nodes must
re-enroll. Requires `--yes`. Use only if the CA private key is suspected
compromised.

---

## `sluice cert expiry`

Prints the current server cert's Common Name and SHA-256 fingerprint.
(Days-until-expiry is on the v0.3 roadmap.)
