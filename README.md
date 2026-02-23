# Reason Proxy

A specialized HTTP/HTTPS audit proxy designed for AI agents and automated systems.

## The Concept

When granting an LLM agent or automated process access to the internet, traditional firewalls provide **access control** (allow/deny domains) but lack **intent visibility**. You know *what* the agent accessed, but not *why*.

**Reason Proxy** solves this by enforcing a cognitive friction layer:

> **Every outbound request must include an `X-Reason` header explaining the intent.**

If the header is missing, the request is rejected (400 Bad Request). If present, the request is logged with the reason, providing a human-readable audit trail of the agent's thought process alongside its network activity.

## Features

-   **Header Enforcement:** Blocks any HTTP request missing the `X-Reason` header.
-   **Structured Logging:** Outputs JSON logs containing:
    -   Timestamp
    -   Source IP
    -   Target URL/Host
    -   Method (GET/POST/CONNECT)
    -   **The Reason** (from header)
    -   Response Status Code
-   **MITM / CONNECT Support:** Handles HTTPS traffic via HTTP CONNECT tunneling (inspects the initial CONNECT request for the header).
-   **Lightweight:** Written in Go, single binary, zero dependencies.

## Usage

### Starting the Proxy
```bash
# Start on port 8080
./reason-proxy -port 8080
```

### Agent Configuration (Client Side)
Configure your HTTP client or AI agent to route traffic through `localhost:8080` and inject the header.

**Curl Example:**
```bash
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080

# This will FAIL (400 Bad Request)
curl https://example.com

# This will SUCCEED
curl -H "X-Reason: Verifying uptime for project Alpha" https://example.com
```

## Audit Log Example
```json
{
  "time": "2024-03-15T10:00:00Z",
  "src": "127.0.0.1",
  "method": "CONNECT",
  "host": "api.github.com:443",
  "reason": "Checking for new issues in repo/project",
  "action": "allow"
}
```

## Why?

By forcing the agent to articulate a "Reason", you:
1.  **Deter hallucinated actions:** The model must generate a rationale, reducing random/accidental requests.
2.  ** Simplify auditing:** You don't have to guess why an agent visited `stackoverflow.com/questions/12345`. The log tells you: `"Debugging Python generic type error"`.

## License
MIT
