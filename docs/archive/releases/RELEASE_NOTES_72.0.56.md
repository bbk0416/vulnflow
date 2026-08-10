# VulnFlow 72.0.56 — Windows external-validation remediation

VulnFlow 72.0.56 fixes cross-platform defects exposed by an independent Windows 11 / Python 3.13 validation run while keeping SQLite schema 46 unchanged.

The Windows run collected all 610 v45 public tests and produced 120 failures. Forty failures shared one product defect: SQLite backup publication called `os.fsync()` on a read-only descriptor, which Windows rejects with `EBADF`. The snapshot is now opened with a writable descriptor only for the durability barrier; its bytes are not modified.

The release also removes the external OpenSSL executable requirement from SMTP and production Compose rehearsals by generating short-lived self-signed certificates through the already locked `cryptography` package. Compose bind mounts use long syntax so Windows drive-letter paths are not parsed as volume-mode separators. Failure paths always publish a structured JSON report.

The signed offline deployment activation and recovery runtime remains POSIX-only. The individual v95-v104 cases that require those semantics now declare that platform boundary explicitly instead of reporting Windows failures for unsupported `chmod`, advisory-lock, atomic-symlink, and directory-fsync semantics. Windows-capable product and external-validation tests continue to run.

Browser E2E startup now writes Uvicorn output to a file rather than an undrained pipe, and the finding locator is unique. The runtime lock now includes the observed `idna==3.17` transitive closure pin.

Eight v116 regression tests cover the backup durability fix, local certificate generation, long-form Compose mounts, machine-readable Compose failures, runtime closure, POSIX-only test boundaries, and browser harness corrections. The public core contract increases from 610 to 618 collected tests. On Windows, POSIX-only tests are reported as explicit skips rather than passes.
