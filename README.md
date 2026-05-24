# NetForge API

**A High-Performance, Low-Latency REST Control Plane for Linux Netfilter Distributed Firewalls**

NetForge replaces manual, error-prone SSH firewall management with a highly available, programmable, and concurrent REST API. It speaks directly to the Linux kernel via Netlink — no `iptables` subprocess, no shell escaping, zero fork overhead.

---

## Features

| Capability | Details |
|---|---|
| **Firewall rule management** | Create, list, get, and delete nftables rules via JSON REST |
| **IP blacklisting** | One-call drop-all for an IP; automatically backed by a kernel rule |
| **Connection tracking** | Live dump of nf_conntrack flows with state, bytes, and packet counts |
| **Bearer token RBAC** | Stateless auth; rotate tokens with a process restart |
| **Dry-run mode** | Full API surface without kernel access — safe for development |
| **Structured logging** | JSON logs via `go.uber.org/zap` with request latency on every call |
| **Graceful shutdown** | 10-second drain on SIGINT / SIGTERM |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     HTTP Client                         │
│            curl / Postman / automation script           │
└───────────────────────┬─────────────────────────────────┘
                        │  JSON over HTTPS (Bearer token)
┌───────────────────────▼─────────────────────────────────┐
│                   NetForge API                          │
│  ┌─────────┐  ┌───────────┐  ┌────────────────────┐    │
│  │ /rules  │  │/blacklist │  │  /connections       │    │
│  └────┬────┘  └─────┬─────┘  └────────┬───────────┘    │
│       │             │                  │                 │
│  ┌────▼─────────────▼──────┐  ┌───────▼──────────┐     │
│  │   NFTService (Netlink)  │  │ ConntrackService  │     │
│  └────────────┬────────────┘  └───────┬──────────┘     │
└───────────────┼───────────────────────┼─────────────────┘
                │ netlink socket         │ netlink socket
┌───────────────▼───────────────────────▼─────────────────┐
│               Linux Kernel                               │
│         nf_tables          nf_conntrack                  │
└─────────────────────────────────────────────────────────┘
```

---

## Requirements

- Linux kernel ≥ 4.10 (nf_tables + nf_conntrack)
- Go 1.22+
- `CAP_NET_ADMIN` capability (or run as root) for live kernel access
- `nf_tables` kernel module loaded (`modprobe nf_tables`)

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Alexmaster12345/netforge-api.git
cd netforge-api

# 2. Install dependencies
go mod tidy

# 3. Configure
cp .env.example .env
# Edit .env — at minimum change NETFORGE_API_TOKENS

# 4a. Run in dry-run (no root needed)
make run

# 4b. Run with real kernel access
make run-root
```

The API listens on `:8090` by default.

---

## Configuration

All configuration is via environment variables (or a `.env` file in the working directory).

| Variable | Default | Description |
|---|---|---|
| `NETFORGE_ADDR` | `:8090` | Listen address |
| `NETFORGE_API_TOKENS` | `changeme` | Comma-separated bearer tokens |
| `NETFORGE_NFT_TABLE` | `netforge` | nftables table name |
| `NETFORGE_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `NETFORGE_DRY_RUN` | `false` | Skip kernel calls |

Generate a secure token:
```bash
openssl rand -hex 32
```

---

## API Reference

All authenticated endpoints require:
```
Authorization: Bearer <token>
```

### Health

#### `GET /api/v1/health`
No auth required.

**Response 200**
```json
{
  "data": {
    "status": "ok",
    "uptime": "3h24m10s",
    "go": "go1.22.4",
    "platform": "linux/amd64"
  }
}
```

---

### Firewall Rules

#### `POST /api/v1/firewall/rules`
Create a new nftables rule.

**Request body**
```json
{
  "direction":        "ingress",
  "source_ip":        "203.0.113.5",
  "destination_port": 443,
  "protocol":         "tcp",
  "action":           "drop",
  "comment":          "block attacker"
}
```

| Field | Type | Required | Values |
|---|---|---|---|
| `direction` | string | yes | `ingress`, `egress` |
| `action` | string | yes | `accept`, `drop`, `reject` |
| `source_ip` | string | no | valid IPv4 |
| `destination_port` | int | no | 1–65535 |
| `protocol` | string | no | `tcp`, `udp`, `icmp` |
| `comment` | string | no | free text |

**Response 201**
```json
{
  "data": {
    "id":               "550e8400-e29b-41d4-a716-446655440000",
    "direction":        "ingress",
    "source_ip":        "203.0.113.5",
    "destination_port": 443,
    "protocol":         "tcp",
    "action":           "drop",
    "comment":          "block attacker",
    "created_at":       "2025-06-01T12:00:00Z"
  }
}
```

---

#### `GET /api/v1/firewall/rules`
List all rules.

**Response 200**
```json
{
  "data": {
    "rules": [ ... ],
    "total": 3
  }
}
```

---

#### `GET /api/v1/firewall/rules/{id}`
Get a single rule by UUID.

**Response 200** — rule object  
**Response 404** — rule not found

---

#### `DELETE /api/v1/firewall/rules/{id}`
Delete a rule from the kernel and store.

**Response 200**
```json
{ "data": { "deleted": "550e8400-e29b-41d4-a716-446655440000" } }
```

---

### IP Blacklist

#### `POST /api/v1/firewall/blacklist`
Blacklist an IP (adds a drop-all ingress rule automatically).

**Request body**
```json
{
  "ip":      "198.51.100.42",
  "comment": "port scanner"
}
```

**Response 201**
```json
{
  "data": {
    "ip":      "198.51.100.42",
    "comment": "port scanner",
    "rule_id": "..."
  }
}
```

**Response 409** — IP already blacklisted

---

#### `GET /api/v1/firewall/blacklist`
List all blacklisted IPs.

---

#### `DELETE /api/v1/firewall/blacklist/{ip}`
Remove an IP from the blacklist and delete the underlying kernel rule.

**Response 200**
```json
{ "data": { "removed": "198.51.100.42" } }
```

---

### Connection Tracking

#### `GET /api/v1/connections`
Dump live flows from `nf_conntrack`.

**Response 200**
```json
{
  "data": {
    "connections": [
      {
        "protocol":    "tcp",
        "source_ip":   "10.0.0.5",
        "source_port": 54321,
        "dest_ip":     "10.0.0.1",
        "dest_port":   443,
        "state":       "ESTABLISHED",
        "packets":     42,
        "bytes":       8192
      }
    ],
    "total": 1
  }
}
```

---

## Error Responses

All errors use the same envelope:

```json
{ "error": "human-readable message" }
```

| Status | Meaning |
|---|---|
| 400 | Malformed JSON |
| 401 | Missing `Authorization` header |
| 403 | Invalid or revoked token |
| 404 | Resource not found |
| 409 | Conflict (e.g. IP already blacklisted) |
| 422 | Validation error (bad IP, port out of range, etc.) |
| 500 | Kernel / internal error |

---

## Development

```bash
# Build binary
make build

# Run tests
make test

# Lint (requires golangci-lint)
make lint

# Clean build artefacts
make clean
```

### Dry-run mode

Set `NETFORGE_DRY_RUN=true` to run the full API without kernel access. All write operations are logged but no Netlink calls are made. The connections endpoint returns an empty list.

---

## Deployment (systemd)

```ini
# /etc/systemd/system/netforge.service
[Unit]
Description=NetForge API
After=network.target

[Service]
ExecStart=/usr/local/bin/netforge
EnvironmentFile=/etc/netforge/netforge.env
Restart=on-failure
RestartSec=5s
# Kernel access
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now netforge
```

---

## License

MIT
