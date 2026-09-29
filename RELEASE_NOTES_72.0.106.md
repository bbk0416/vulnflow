# VulnFlow Free — Public Beta 72.0.106

Release date: 2026-09-29

72.0.106 is a maintenance release on the feature-frozen 72.0.72 line. It packages two scanner-import issues found during a maintainer-operated Windows pilot after 72.0.105. It does not add a new product feature, change SQLite schema 46, change prioritization thresholds, or change runtime dependency pins.

## What changed

- Align scanner compatibility reporting with the already-supported CVE-less finding model. Nessus/OpenVAS findings without a CVE are counted as importable when the product identity is valid, while malformed non-empty CVE values remain invalid.
- Update Korean/English import-preview copy so CVE-less findings are no longer described as unsupported; CVE-specific intelligence, VEX, and OSV limitations are stated explicitly instead.
- Reject unsupported XML scanner exports during automatic format detection instead of treating every non-Nessus XML file as OpenVAS.
- Preserve supported NessusClientData_v2 and OpenVAS/Greenbone XML roots, including `report`, `get_reports_response`, and `get_results_response`.
- Add regression coverage for the exact Nmap XML boundary encountered during the pilot without increasing the fixed 731-test public regression contract.

## Verification boundary

- Public regression collection contract remains 731 tests across seven bounded groups.
- Protected public CI still requires 12 contexts on the exact pull-request head; CodeQL `Analyze (actions)` and `Analyze (python)` are also required before publication.
- Windows/Python 3.13 builds and re-verifies the exact-tree Windows release candidate.
- SQLite schema remains 46 and runtime dependency pins remain unchanged.
- Maintainer-operated Windows pilot coverage includes install, login, Nessus import, assignment, remediation, two complete-snapshot absences, verification approval, final `CLOSED`, CVE-less compatibility behavior, and rejection of an existing local Nmap XML export.
- No real organization Nessus/OpenVAS/Greenbone result file was available on the pilot PC, so real-customer scanner-output validation remains NOT_TESTED.
- 24-hour endurance, sustained production-scale capacity, rootless Docker, Kubernetes, and real external proxy/NAS/firewall/ACL environments remain outside the claimed verification boundary.
