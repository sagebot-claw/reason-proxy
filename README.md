# Reason Proxy (MITM Edition)

A specialized Man-in-the-Middle (MITM) audit proxy designed for AI agents and automated systems.

## The Concept

When granting an LLM agent or automated process access to the internet, traditional firewalls provide **access control** (allow/deny domains) but lack **intent visibility**. You know *what* the agent accessed, but not *why*.

**Reason Proxy** solves this by enforcing a cognitive friction layer:

> **Every outbound request must include an `X-Reason` header explaining the intent.**

If the header is missing, the request is rejected (400 Bad Request). If present, the request is logged—including the full decrypted payload—providing a forensic audit trail of the agent's thought process alongside its network activity.

## Features

-   **Deep Inspection (MITM):** Decrypts HTTPS traffic to inspect headers and log payloads.
-   **Header Enforcement:** Blocks any request missing the `X-Reason` header.
-   **SQLite Audit Log:** Stores structured logs (headers, bodies, reasons) in a local `audit.db` file for easy querying.
-   **Automatic CA Generation:** Generates a root CA on first run to sign on-the-fly certificates for intercepted domains.

## Usage

### 1. Build & Start
```bash
go build
./reason-proxy -port 8080 -db audit.db
```

On first run, it will generate `ca.pem` and `ca.key`.

### 2. Trust the CA (Client Side)
For the agent to trust the proxy's fake certificates, you must add `ca.pem` to the agent's trust store.
*   **Linux/Docker:** Copy `ca.pem` to `/usr/local/share/ca-certificates/reason-proxy.crt` and run `update-ca-certificates`.
*   **Node.js:** Set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.
*   **Python (Requests):** Set `REQUESTS_CA_BUNDLE=/path/to/ca.pem`.

### 3. Agent Configuration
Configure your HTTP client to use the proxy and inject the header.

**Curl Example:**
```bash
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080
export REQUESTS_CA_BUNDLE=./ca.pem

# This will SUCCEED and be logged to SQLite
curl -H "X-Reason: Verifying uptime" https://example.com
```

## Audit Log Schema

The `audit_log` table contains:
-   `timestamp`: When it happened.
-   `method`, `url`, `host`: The target.
-   `reason`: The agent's stated intent.
-   `req_headers`, `req_body`: The full request (truncated to 4KB).
-   `resp_status`, `resp_body`: The full response (truncated to 4KB).
-   `action`: "ALLOW" or "DENY".

## License
MIT
