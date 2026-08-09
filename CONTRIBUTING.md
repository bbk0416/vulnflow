# Contributing to VulnFlow

VulnFlow Free is a public-beta, MIT-licensed local vulnerability-remediation closeout project. Contributions are welcome when they improve correctness, clarity, testability, scanner compatibility, or the core workflow without overstating operational maturity or customer validation.

## Before opening a change

- Do not submit real military, government, customer, or company vulnerability data.
- Do not include credentials, API tokens, private keys, personal contact details, or local user paths.
- Use synthetic fixtures and `example.test` domains only.
- Keep the default deployment bound to loopback unless the change also documents authentication and TLS requirements.
- Do not describe VulnFlow as a scanner, autonomous impact-analysis engine, multi-tenant SaaS, or production-proven enterprise platform.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/run_public_tests.py
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python scripts/run_public_tests.py
```

## Pull requests

A pull request should:

1. Explain the operational problem being addressed.
2. Describe the implementation boundary and tradeoffs.
3. Add or update tests for changed behavior.
4. Update user-facing documentation when behavior changes.
5. Confirm that no sensitive or real-world vulnerability data is included.

Large features should start as a discussion or feature-request issue. Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public issue.

## Scope preference

Priority is given to:

- scanner-result normalization and reconciliation;
- prioritization and remediation workflow clarity;
- evidence, audit, backup, and recovery correctness;
- integrations that can be tested with synthetic data;
- usability and accessibility improvements;
- simpler implementations that reduce operational complexity.

Cryptographic proof, release-supply-chain, or distributed coordination features should include a clear threat model and must not obscure the primary vulnerability-management workflow.


## Free core and future commercial editions

This public repository is the MIT-licensed Free core. Contributions accepted here remain part of that public core under the repository license.

Do not submit confidential, customer-owned, employer-owned, or proprietary commercial code. A future paid VulnFlow edition may be developed separately; public pull requests should not assume that an unannounced Pro feature or price exists.

During Free Public Beta, feature requests are prioritized by demonstrated scanner compatibility defects, repeated workflow blockers, security/reliability issues, and concrete target-user requirements. Feature-count expansion alone is not a reason to merge a change.
