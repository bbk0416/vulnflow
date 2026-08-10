# VulnFlow 72.0.16

## Customer and project isolation

This release introduces customer/project workspaces without rewriting the existing finding repositories. The legacy database becomes the default project, while each additional project receives a separate SQLite database and separate evidence, export, import-preview, and recovery directories.

### User-visible changes

- Adds a project selector to the authenticated header.
- Adds an administrator page for project creation, activation, and user assignment.
- Limits normal users to assigned projects.
- Allows Bearer API tokens to declare explicit project scopes or `"projects": "*"`.
- Defaults unscoped API tokens to the legacy/default project only.
- Clears the selected-project cookie at logout.

### Storage and upgrade behavior

- Advances SQLite schema from 41 to 42.
- Migrates existing users and data into the `default` project without moving the legacy database.
- Creates every non-default project under `data/projects/<project-id>/` with its own database and storage directories.
- Runs the background job worker across active project queues using round-robin project selection.
- Removes a partially created project directory and registry record when project initialization fails.

### Verification

- Adds ten project-isolation regression tests covering schema migration, physical data separation, browser switching, membership enforcement, Bearer scope enforcement, child-project background jobs, and logout cleanup.
- Expands the public core suite from 273 to 283 tests.

### Known boundaries

- The project registry and browser accounts remain in the legacy control database.
- Startup integrity checks and scheduled maintenance remain centered on the default/control project; per-project integrity status and scheduler fan-out require a later release.
- This is single-host physical isolation, not multi-tenant SaaS isolation or a substitute for operating-system access controls.
