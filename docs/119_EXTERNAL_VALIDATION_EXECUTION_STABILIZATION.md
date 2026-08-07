# External validation execution stabilization

VulnFlow 72.0.58 addresses three external-validation failures observed on Windows after all supported public regression tests passed.

## Production Compose direct execution

The rehearsal is invoked as `python scripts/production_compose_rehearsal.py`. Python places the `scripts/` directory, not the repository root, at the start of `sys.path` for that form of execution. The script now inserts its resolved repository root before importing `scripts.local_tls_certificate`. The existing JSON failure-report contract remains unchanged.

## Browser workflow visibility

Playwright assertions are scoped to visible success notices. Approval-history text lives inside a collapsed `details` element, so the E2E workflow opens that disclosure before asserting the approved request. This preserves the user interface rather than weakening the assertion to hidden DOM presence.

## Runtime allocation warm-up

The bounded soak continues to enforce a 24 MiB Python allocation-growth limit, but starts `tracemalloc` only after three complete warm-up lifespans by default. RSS is still sampled across every cycle. This separates one-time lazy initialization from steady-state growth while retaining leak detection across the remaining measured cycles. Reports expose actual and limit bytes.
