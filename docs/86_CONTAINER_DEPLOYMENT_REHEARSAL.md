# Container-equivalent deployment rehearsal

`scripts/container_deployment_rehearsal.py` validates the Docker and Compose contract and runs the application with container-equivalent restrictions when a Docker engine is unavailable.

The rehearsal checks non-root execution, read-only source code, writable persistent data, explicit project-scoped API tokens, separated control/project databases, health endpoints, restart persistence, SQLite integrity, and schema compatibility across repeated cycles.

```bash
python scripts/container_deployment_rehearsal.py --cycles 2
```

Passing this rehearsal does not prove a current Docker image build, Docker networking, volume-driver behavior, orchestration health, or production certificate configuration. Those require an actual Docker or compatible container engine.
