# Tasker

Tasker is the orchestration component in the [Falcoria](https://github.com/Falcoria/falcoria) distributed scanning system. It sits between the user (via falcli or API) and the workers. When a scan is submitted, Tasker prepares the targets before anything gets scanned: expands CIDRs, resolves hostnames, removes duplicates, and checks what's already been scanned or queued.

The output is a set of discrete scan tasks, each targeting a single IP with a defined port range. Tasks go into the queue (RabbitMQ), workers pick them up.

## Quick start

The fastest way to run everything (ScanLedger + Tasker + Worker + Postgres + Redis + RabbitMQ):

```bash
git clone https://github.com/Falcoria/falcoria.git
cd falcoria
./quickstart.sh
```

See the [all-in-one repo](https://github.com/Falcoria/falcoria) for details.

## Standalone setup

For distributed deployments where Tasker runs on its own machine:

```bash
git clone https://github.com/Falcoria/tasker.git
cd tasker
cp .env.example .env  # edit connection settings
```

### Docker

```bash
docker compose up --build
```

### Manual (development)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.app:fastapi_app --host 0.0.0.0 --port 8001
```

Tasker runs on port `8443` (HTTPS) in Docker, `8001` in development. API docs at `/docs`.

## Configuration

Environment variables in `.env`:

- Redis and RabbitMQ connection details
- ScanLedger URL and token (Tasker checks ScanLedger for already-scanned targets)
- TLS settings

See `app/config.py` for all options.

## API endpoints

- `POST /tasks/{project_id}/run-nmap` — submit targets for scanning
- `GET /tasks/{project_id}/status` — current scan status
- `GET /tasks/{project_id}/stop-nmap` — stop running scans and clear queue
- `GET /workers/ips` — list active worker IPs
- `GET /health` — health check

In practice, these are called through [falcli](https://github.com/Falcoria/falcli) rather than directly.

## Documentation

Full documentation: [https://falcoria.github.io/falcoria-docs/](https://falcoria.github.io/falcoria-docs/)

- [Architecture](https://falcoria.github.io/falcoria-docs/architecture/) — how Tasker fits into the system
- [Deduplication](https://falcoria.github.io/falcoria-docs/concepts/deduplication/) — what happens to targets before scanning
- [Distribution](https://falcoria.github.io/falcoria-docs/concepts/distribution/) — distributed scanning model

## License

MIT
