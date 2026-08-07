# Windows path-contract completion

The v46 Windows external-validation run passed six of seven bounded public groups. The only remaining failure was `test_rehearsal_environments_use_split_storage_and_scoped_tokens`, which compared a valid Windows path ending in `projects\default\vulnflow.db` against a POSIX-only string ending in `projects/default/vulnflow.db`.

VulnFlow 72.0.57 compares path components after normalizing separators. The runtime environment functions remain unchanged. The regression includes synthetic Windows and POSIX paths so the contract is testable on either host platform.
