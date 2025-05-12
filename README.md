# Tasker

Tasker is the orchestration service in the Falcoryon system. It distributes scan tasks to workers and manages scan lifecycles using HTTP APIs.

## Features

- Sends validated scan requests to distributed workers.
- Uses scan configs (YAML) and project context.
- Tracks scan phases and status.
- Supports chaining logic for multi-phase scans (e.g., ports → services).
- Integrates with ScanLedger and Worker agents.

## Usage

Use the `falc.py` CLI to trigger scans. Tasker handles task distribution and interacts with workers and ScanLedger to store results.

## License

MIT
