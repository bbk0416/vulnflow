# VulnFlow 72.0.60 — Isolated router runtime release

VulnFlow 72.0.60 keeps SQLite schema 46 and adds no product feature. It closes the last Windows external-validation failure by releasing the application back-reference held by each isolated router module after lifespan shutdown.

## Evidence

The independent Windows 72.0.59 attribution run showed one retained FastAPI application, 276 APIRoute objects, 16 cloned router modules, and roughly 11.16 MiB of Python allocations per completed lifecycle. The retained graph was rooted by the injected `app` value in cloned module globals.

## Change

- Isolated router modules remove only their owning `app` reference after shutdown.
- The process-level compatibility application is not released.
- A later lifespan startup rebinds the application and complete dependency namespace, preserving application restart behavior.
- Allocation limits remain unchanged.

## Regression contract

Four v119 tests cover release, restart, repeated garbage collection, and primary-runtime preservation. The public core suite contains 631 tests plus three separate Chromium E2E tests.
