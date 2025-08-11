
# Tasker

Tasker is the orchestration service in the Falcoria system. It distributes scan tasks to workers, manages scan lifecycles, and tracks scan status using HTTP APIs and Celery.

## Features

- **Distributed Scanning:** Sends validated scan requests to distributed workers using Celery and RabbitMQ.
- **Flexible Input:** Accepts hostnames, IPs, and CIDRs; deduplicates and resolves hostnames to IPs.
- **Scan Tracking:** Tracks scan status, phases, and results using Redis and ScanLedger.
- **Multi-phase Scans:** Supports chaining logic for multi-phase scans (e.g., open ports → service detection).
- **API-First:** Exposes a FastAPI-based HTTP API for scan management and status.
- **Worker Management:** Tracks worker status and IPs.
- **Secure:** Supports TLS for secure communication.
- **Extensible:** Integrates with ScanLedger and Worker agents for result storage and worker management.

## Architecture

- **API:** FastAPI app (`app/`) exposes endpoints for scan management under `/tasks`.
- **Task Distribution:** Uses Celery with RabbitMQ for distributing scan jobs to workers.
- **State Tracking:** Uses Redis for tracking scan tasks, locks, and worker status.
- **ScanLedger Integration:** Communicates with ScanLedger for known targets and result storage.
- **Workers:** Separate worker services execute scan tasks and report results.

## Endpoints

- `POST /tasks/{project_id}/run-nmap`  
	Start a new scan for a project. Accepts a JSON body with hosts and scan options.

- `GET /tasks/{project_id}/status`  
	Get the current scan status for a project.

- `GET /tasks/{project_id}/stop-nmap`  
	Stop all running scans for a project.

- `GET /workers/ips`  
	List all known worker IPs.

- `GET /health`  
	Health check endpoint.

## Usage

1. **Start the API server:**
	 ```bash
	 uvicorn app.app:fastapi_app --reload --host 0.0.0.0 --port 8001
	 ```

2. **Start Celery workers:**
	 ```bash
	 celery -A app.celery_app.celery_app worker --loglevel=info
	 ```

3. **Trigger a scan via API or CLI:**
	 - Use the `/tasks/{project_id}/run-nmap` endpoint or the `falc.py` CLI tool.

4. **Check scan status:**
	 - Use `/tasks/{project_id}/status` or the CLI.

5. **Stop scans:**
	 - Use `/tasks/{project_id}/stop-nmap`.

## Configuration

Configuration is managed via environment variables or `.env` file. See `app/config.py` for all options, including:
- Redis and RabbitMQ connection details
- Logger settings
- TLS certificate generation (`generate-tls-bundle.sh`)

## Development

- Install dependencies:
	```bash
	pip install -r requirements.txt
	```
- Install `falcoria-common` in editable mode if developing locally:
	```bash
	pip install -e ../falcoria-common
	```
- Run tests (if available):
	```bash
	pytest
	```

## Notes

- Large scan results: Only the first 100 results may be printed to the user; the full result is saved to a file.
- Hostname resolution: Multiple hostnames resolving to the same IP are tracked and reported.
- All API responses are JSON.

## License

MIT
