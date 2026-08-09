# VulnFlow 72.0.58 — external validation execution stabilization

VulnFlow 72.0.58 keeps SQLite schema 46 and does not add product features. It fixes three issues found only after the Windows v47 external-validation run:

- `scripts/production_compose_rehearsal.py` now bootstraps the repository root before importing the shared certificate generator, so direct script execution produces a structured Docker availability or rehearsal report instead of `ModuleNotFoundError`.
- Browser workflow E2E assertions now scope success notices to visible success elements and explicitly open the collapsed approval-history section before asserting the approved request.
- The bounded runtime soak now starts `tracemalloc` after configurable warm-up lifespans. The 24 MiB steady-state allocation-growth limit remains unchanged, and reports include actual bytes, limit bytes, availability, and measured-sample count.

The release adds v117 regression coverage. Docker runtime, unrestricted Windows Chromium, and the Windows bounded soak still require independent Windows execution after packaging.
