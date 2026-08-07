# VulnFlow 72.0.43 — Recovery-journal key lifecycle

Release date: 2026-08-04
SQLite schema: 46

## Fixed

- Added explicit status, backup, restore, and rotation commands for the private recovery-journal HMAC key.
- Bound backup files to the deployment target name and validated their format, key length, and fingerprint before use.
- Required a restored key to authenticate every pending v3 journal and its actual previous-keyring and previous-audit inventory before changing the live key path.
- Refused silent replacement of an available key from an older backup when no matching pending journal exists; explicit rotation is required instead.
- Blocked journal-key rotation while any interrupted recovery transaction is pending.
- Made journal-key rotation atomic with authenticated audit recording and automatic restoration of the previous key if the audit append fails.
- Removed a newly created key backup if its audit event cannot be committed.
- Added exact management-CLI coverage for key status, backup, and rotation.

## Verification

- Public core regression contract: 503 tests in five bounded groups.
- Chromium browser E2E remains a separate three-test contract.
- New recovery-journal key lifecycle regression contract: 10 tests.
- Combined journal recovery, authentication, startup-preflight, and key-lifecycle focused contract: 36 tests.
- SQLite schema remains 46.

## Limitations

The backup contains the raw symmetric journal key and is protected only by file permissions; VulnFlow does not encrypt it. It must be stored on encrypted offline media. A restore performed while a journal is pending authenticates that journal but does not itself complete the interrupted history recovery; startup preflight or the explicit recovery command must run afterward.
