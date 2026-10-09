# Uptime Monitor Service

A self-hosted service availability and health monitoring platform with a web dashboard, configurable checks, incident history, notifications, audit events, and report exports.

> **Status:** Active development. Review the security and deployment notes before exposing an instance to a network.

## Features

- Central dashboard for service status and availability history
- Multiple monitor types, including HTTP(S), ICMP/Ping, TCP, DNS, TLS/SSL, SMTP, MySQL, PostgreSQL, and Redis (availability depends on the configured check)
- Incident tracking, event history, and audit records
- Notification groups, templates, and supported integrations
- Service details, screenshots, on-demand checks, and report exports
- User and role management
- PostgreSQL persistence, Redis-backed cache, and a Caddy reverse proxy
- Docker Compose deployment

## Architecture

```text
Browser
  │ HTTP :80 / HTTPS :443
  ▼
Caddy reverse proxy
  │ internal Docker network
  ▼
FastAPI + Uvicorn ───── Redis cache
  │
  ▼
PostgreSQL
```

The application listens on port `8080` inside its container. The Compose file publishes `80` and `443` through Caddy and also retains a configurable direct application port for troubleshooting.

## Quick start (Docker Compose)

### Requirements

- Docker Engine with the Compose plugin
- Available host ports `80`, `443`, and (by default) `8080`
- Outbound network access from the host/container for checks against monitored targets

### 1. Configure environment variables

```bash
cp .env.example .env
```

Generate a fresh secret and put the output in `.env` as `JWT_SECRET`:

```bash
openssl rand -hex 32
```

Set unique values for `POSTGRES_PASSWORD` and `JWT_SECRET` before starting. Do not commit `.env` or production credentials.

### 2. Start the stack

```bash
docker compose up -d --build
```

Check service health and logs:

```bash
docker compose ps
docker compose logs -f app
```

Open the dashboard at:

- `http://localhost/` (Caddy on port 80)
- `https://localhost/` (Caddy's local internal certificate)
- `http://localhost:8080/` (direct app port, if enabled in Compose)

**HTTPS note:** the default Caddy configuration uses an internal CA. Browsers will normally show a certificate trust warning until that CA is trusted. For internet-facing production deployments, configure a real domain and a publicly trusted certificate.

### 3. Initial account

The current application bootstrap may provide the initial credentials `admin / admin`. If this account is enabled in your build, sign in only on a trusted network and change the password immediately. Do not expose an instance with default credentials.

## Configuration

All deployment-specific settings are read from environment variables. See [`.env.example`](.env.example).

| Variable | Purpose |
|---|---|
| `POSTGRES_DB` | PostgreSQL database name |
| `POSTGRES_USER` | PostgreSQL application user |
| `POSTGRES_PASSWORD` | PostgreSQL password; set a unique value |
| `JWT_SECRET` | Secret used for signing authentication tokens; generate a unique random value |
| `APP_PORT` | Optional host port for direct access to the application (default `8080`) |
| `COOKIE_SECURE` | Set to `true` when the application is accessed over HTTPS and cookie behavior is configured accordingly |
| `TZ` | Time zone used by the container |
| `REDIS_URL` | Redis connection URL |

Do not use the sample values for a production deployment. If the app is exposed only through Caddy, consider removing the `app` service's host `ports` mapping after verifying proxy access, so port `8080` is not directly reachable from the host network.

## Useful commands

```bash
# Show container status
docker compose ps

# Follow application logs
docker compose logs -f app

# Restart the stack
docker compose restart

# Stop the stack without deleting persistent volumes
docker compose down

# Stop and delete persistent volumes (DESTRUCTIVE: removes stored database and screenshots)
# docker compose down -v
```

PostgreSQL data, screenshots, uploaded branding assets, and Caddy state are stored in Docker volumes. Back up important data before upgrades or destructive operations.

## Repository layout

```text
.
├── backend/              # FastAPI application, models, authentication, checks
├── frontend/             # HTML, CSS, JavaScript, and static assets
├── docs/                 # API documentation
├── Dockerfile
├── docker-compose.yml
├── Caddyfile
├── requirements.txt
├── .env.example
└── README.md
```

## Security checklist

- [ ] Set a unique `JWT_SECRET` and strong database password.
- [ ] Change the initial administrator password immediately.
- [ ] Use trusted HTTPS for production and set secure cookie behavior appropriately.
- [ ] Do not expose PostgreSQL or Redis ports publicly.
- [ ] Restrict who can access the dashboard and who can create/edit monitors.
- [ ] Back up PostgreSQL and test restoration periodically.
- [ ] Keep dependencies and base images updated.
- [ ] Never commit `.env`, databases, logs, screenshots, credentials, tokens, or customer-specific monitor lists.
- [ ] Review outbound monitoring permissions and network egress policy before deploying.

## Development

Install the dependencies in a virtual environment if you want to run the application outside Docker:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

For a deployment-like environment, Docker Compose is recommended because it also provides PostgreSQL, Redis, and Caddy. Some checks require system-level network tools and may behave differently outside the provided container.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Report security issues privately as described in [`SECURITY.md`](SECURITY.md).

## License

No license has been added yet. Unless a license is included by the project owner, standard copyright restrictions apply; contact the repository owner before redistributing or reusing this code.
