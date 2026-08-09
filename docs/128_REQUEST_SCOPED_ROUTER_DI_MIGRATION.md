# Request-scoped router DI migration

## 72.0.68 boundary

The pilot router is the first domain router that no longer receives application dependencies by writing names into module globals. Its endpoint functions use a FastAPI dependency to resolve the `ApplicationContext` owned by `request.app`, and services and settings are then resolved from that context for the current request.

```text
request
  -> request.app.state.vulnflow_context
  -> ApplicationContext
  -> immutable settings and service container
  -> project-scoped path values
```

The endpoint functions and source `APIRouter` are shared across application instances. They contain no application, database path, or service instance in their module globals. This permits normal FastAPI router registration without cloning the endpoint function or rebuilding the source route metadata.

## Mixed migration runtime

The migration is intentionally incremental:

- `pilot`: request-scoped context dependency; shared imported endpoint functions; normal router registration.
- remaining 15 router modules: 72.0.67 in-memory namespace and APIRoute cloning compatibility path.

The application route table remains 276 routes. Secondary application shutdown releases all routes and endpoints created for that application; shared pilot endpoints remain process-level module functions by design and do not own an application reference.

## Isolation contract

The regression suite starts two independent applications, authenticates to each, stores different pilot customer profiles, synchronizes both threads, and repeatedly calls the same shared `pilot_readiness_api` endpoint concurrently. Every response must come from the owning application's project database.

## Remaining work

Each remaining router must remove dependency reads from module globals before it can join `CONTEXT_ROUTER_MODULES`. Only after the final router migration can VulnFlow delete `app/router_cloning.py`, private runtime namespaces, direct APIRoute transfer, and FastAPI callable-cache cleanup.
