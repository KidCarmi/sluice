# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Sluice, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security@kidcarmi.com with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Design

Sluice follows Secure Software Development Lifecycle (SSDLC) practices:

- All dependencies pinned in go.mod
- CI runs gosec, govulncheck, trivy, and gitleaks on every commit
- No unsafe package usage
- No os/exec calls
- All file I/O bounded by io.LimitReader
- All paths validated against traversal attacks
- mTLS for all gRPC communication
- Structured logging with no raw user content
