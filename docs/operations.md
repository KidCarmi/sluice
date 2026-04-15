# Sluice Operations Runbook

Day-2 operations for operators running Sluice — whether co-located with a
single Culvert, shared across a team, or deployed as a dedicated fleet.

---

## Backup & disaster recovery

Everything that needs to survive an outage lives under `/data` (the
`sluice-data` volume in compose).

### What to back up

| Path | Priority | If lost |
|---|---|---|
| `/data/ca.pem`, `/data/ca-key.pem` | **Mandatory** | Every Culvert must re-enroll. CA has 10-year validity — back it up once, rotate only on compromise. |
| `/data/server.pem`, `/data/server-key.pem` | Nice to have | Regenerated automatically by `BootstrapServerCerts` on daemon start if missing. Fingerprint changes — plan for server-rotate afterward. |
| `/data/clients.json` | Recommended | Revocation history lost. Existing client certs still work (they're valid against the CA); you lose the ability to enumerate/revoke by fingerprint until RenewCert repopulates. |
| `/data/enrollment_token` | Discardable | Regenerate with `sluice token rotate`. |
| `/data/ui_token` | Discardable | Auto-regenerated on next daemon start. |

### Minimum backup

```bash
docker exec culvert-sluice tar -C /data -cf - ca.pem ca-key.pem clients.json \
  | gpg --encrypt --recipient ops@your-org > sluice-backup-$(date +%F).tar.gpg
```

Store the GPG-encrypted archive in your existing secret manager (Vault,
sealed-secrets, AWS Secrets Manager, etc.) — the CA private key has the
same blast radius as any other root signing key.

### Restore

```bash
# On the new host, before the daemon starts:
gpg --decrypt sluice-backup-YYYY-MM-DD.tar.gpg | docker run -i --rm \
  -v sluice-data:/data --entrypoint tar \
  ghcr.io/kidcarmi/sluice:latest -C /data -xf -

# Then start normally:
docker compose up -d sluice
```

All Culverts keep working — their client certs were signed by the CA you
just restored, and the ledger knows them. Server cert is regenerated from
the restored CA on first boot.

---

## Upgrade

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

Sluice is stateless; no migrations. Enrolled clients keep working —
their certs are signed by the persistent CA in `/data/tls/ca.pem`.

---

## Rotate server certificate (zero downtime)

```bash
docker exec culvert-sluice sluice cert server-rotate --grace 24h
docker restart culvert-sluice
```

What happens:
1. The command mints a fresh server cert signed by the existing CA.
2. Culvert's next Health call sees `rotated_fingerprint=<old>` +
   `rotated_fingerprint_until_unix=<now+24h>` and auto-rewrites its
   pinned fingerprint to the new one.
3. The old fingerprint stops being accepted by Culvert after the grace
   window. Existing mTLS client certs are unaffected — the CA didn't
   change.

No operator action required on the Culvert side.

---

## Rotate CA (forces re-enrollment)

```bash
docker exec culvert-sluice sluice cert ca-rotate --yes
docker restart culvert-sluice
docker exec culvert-sluice sluice token
# → paste the new token + fingerprint into Culvert's enroll UI for each instance
```

This invalidates every client cert and wipes the ledger. Use only when
you suspect the CA key was compromised. Culvert nodes will see handshake
failures until they re-enroll.

---

## Recover a lost enrollment token

If the token file was rotated out before Culvert consumed it:

```bash
docker exec culvert-sluice sluice token rotate
```

Old tokens are revoked; a new token + fingerprint is printed.

---

## Revoke a compromised Culvert node

```bash
# Look up the fingerprint
docker exec culvert-sluice sluice node list

# Revoke by fingerprint (sync: in effect on next RPC)
docker exec culvert-sluice sluice node revoke --reason "suspected compromise" sha256:a1b2c3...
```

The revoked node's next RPC fails with `PermissionDenied`. Persisted
to `/data/clients.json` so it survives daemon restarts.

**Emergency — revoke every active client without minting a fresh CA:**

```bash
docker exec culvert-sluice sluice node revoke-all --yes --reason "mass rotation"
```

All Culvert nodes must re-enroll afterward. Use this instead of
`ca-rotate` when you want a fast sweep without distributing a new CA
fingerprint.

---

## Draining / decommissioning

1. In Culvert's admin UI, remove the Sluice instance from the policy
   (stop sending it traffic).
2. Wait for in-flight requests to drain (max ~30s given the
   `workers.timeout`).
3. Stop the container:
   ```bash
   docker compose -f deploy/docker-compose.yml down
   ```
4. Sluice's `GracefulStop` honors in-flight streams up to 35s before
   forcing a shutdown.

---

## Read Prometheus metrics

Scrape `http://127.0.0.1:9090/metrics`. Key series:

| Metric | Meaning |
|--------|---------|
| `sluice_files_processed_total{profile, mode, status}` | Counter of sanitize requests |
| `sluice_threats_removed_total{type, severity}` | Threats neutralized |
| `sluice_duration_seconds{profile}` | Histogram of sanitize wall-clock time |
| `sluice_active_workers` | Gauge of currently-busy workers |
| `sluice_queue_depth` | Gauge of backlog |
| `sluice_testing_ui_uploads_total{ui_test="true"}` | Separated to avoid polluting prod metrics |

Expected SLOs (see `docs/benchmarks.md` — pending):
- p50 sanitize latency for a 1 MB PDF: < 20 ms
- p99 for a 50 MB DOCX: < 2 s

---

## Disable the testing UI for production

Edit your config.yaml or use the production compose overlay:

```yaml
testing_ui:
  enabled: false
```

Or remove the port publication from your compose file:

```yaml
ports:
  - "127.0.0.1:8443:8443"   # gRPC only
  # (no 8080 entry)
```

---

## Emergency: disable all inbound traffic

```bash
docker network disconnect <bridge-name> culvert-sluice
```

Active streams finish draining via the graceful-stop path; no new
connections accepted. When you're ready:

```bash
docker network connect <bridge-name> culvert-sluice
```

---

## Logs

Default output is JSON on stdout. Capture with:

```bash
docker logs -f culvert-sluice
```

Every `Sanitize` call produces a log line with:

```json
{
  "time": "…",
  "level": "INFO",
  "msg": "file sanitized",
  "rpc": "Sanitize",
  "request_id": "…",
  "trace_parent": "00-…",
  "profile": "default",
  "mode": "ENFORCE",
  "policy_version": "…",
  "type": "pdf",
  "status": "SANITIZED",
  "threats": 3,
  "duration_ms": 42
}
```

Correlate with Culvert's audit log using `request_id` and `trace_parent`.

---

## Known issues

- `sluice token` issued on a CLI invocation does not populate the running
  daemon's in-memory token set (the daemon keeps hashes in RAM, not on
  disk). For v0.1, operators should restart the daemon after rotating,
  or rely on first-boot token generation. v0.2 will expose a CLI-side
  IssueToken that plumbs through the unix socket.
