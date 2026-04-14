# Sluice Operations Runbook

Day-2 operations for operators running Sluice alongside Culvert.

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
# v0.2 — command exists as a stub today
docker exec culvert-sluice sluice cert server-rotate
```

Until the stub lands, the procedure is:
1. Stop the daemon.
2. Delete `/data/tls/server.pem` and `/data/tls/server-key.pem`
   (leave `ca.pem` and `ca-key.pem` alone).
3. Restart — `BootstrapServerCerts` issues a fresh server cert signed by
   the existing CA. Existing enrolled clients continue to work.

Remember to update Culvert's stored fingerprint after rotation
(`docker exec culvert-sluice sluice fingerprint` → paste into Culvert UI).

---

## Rotate CA (forces re-enrollment)

```bash
# v0.2 — command stub
docker exec culvert-sluice sluice cert ca-rotate
```

This invalidates all issued client certs. Operators must re-run the
enrollment flow for every Culvert node. Use only when you suspect the
CA key was compromised.

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
# v0.2 — command stub
docker exec culvert-sluice sluice node revoke <name>
```

v0.1 workaround: rotate the CA (see above), which invalidates every
client cert, then re-enroll the trustworthy nodes.

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
