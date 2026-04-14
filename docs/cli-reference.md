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

## v0.2 (stubbed / not-yet-implemented)

These commands are part of the planned v0.2 surface and currently exit
with a non-zero code and a "not implemented" message. Listed here so tooling
can be wired against the final names.

| Command | Purpose |
|---------|---------|
| `sluice node list` | List enrolled clients |
| `sluice node show <name>` | Details + cert expiry |
| `sluice node revoke <name>` | Revoke one client |
| `sluice node revoke-all` | Emergency: regen CA |
| `sluice cert server-rotate` | New server cert (zero downtime) |
| `sluice cert ca-rotate` | New CA (forces re-enrollment) |
| `sluice cert expiry` | Days-until-expiry |
| `sluice profile list` | Sanitization profiles |
| `sluice profile show <name>` | Capabilities + limits |
| `sluice ui-token rotate` | Rotate testing UI bearer token |
| `sluice config show` | Dump effective config |
| `sluice config validate <file>` | Lint a config file |

Every command that ships in v0.1 supports `--json` for machine-readable
output. (Flag plumbing lands with v0.2 node/profile commands.)
