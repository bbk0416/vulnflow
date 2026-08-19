# VulnFlow Free — Public Beta 72.0.92

72.0.92 is a **current Greenbone detailed CSV compatibility correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import compatibility defect without changing SQLite schema 46 or dependency package pins.

## Fixed

Current Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT detailed CSV exports use fields including `Vulnerability name`, `CVE references`, host identity columns, and—for affected endpoints—`Port/Protocol`. VulnFlow 72.0.91 recognized earlier `CVEs`/`CVE` aliases but did not recognize `CVE references` as a Greenbone CVE header or value source. The current official profile therefore fell back to generic CSV handling, left canonical `cve_id` empty, and produced zero valid import rows.

72.0.92 recognizes the current Greenbone header profile as `openvas_csv` and extracts CVEs from `CVE references`. Existing Customizable CSV `CVEs`/`VT Name`, legacy `NVT Name`, split `Port` + `Port Protocol`, combined `Port/Protocol`, Greenbone XML, and host-level identity behavior remain backward compatible.

## Regression contract

One new end-to-end regression uses the current detailed-export headers, relies on automatic scanner detection, verifies `CVE references` extraction and distinct `443/tcp` / `8443/tcp` component identities, applies both rows through `apply_import_batch()`, and confirms that both findings are inserted. The public collection contract is now 717 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 131). Platform-specific skips remain explicit and are not represented as executed passes.

## Compatibility

- SQLite schema: **46 (unchanged)**
- Runtime/development dependency package pins: **unchanged**
- Existing scanner adapters and canonical identity rules: **backward compatible**
- Feature scope: **unchanged; defect patch only**
