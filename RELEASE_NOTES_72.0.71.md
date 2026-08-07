# VulnFlow 72.0.71 — concurrent router schema isolation

VulnFlow 72.0.71 removes the remaining Pydantic field-metadata warning that could
appear when two secondary FastAPI applications were assembled concurrently.

Imported router templates have already been analyzed once by FastAPI. That analysis
adds derived parameter state such as the effective alias and annotation to `Form`,
`Header`, and related `FieldInfo` defaults. Reusing or blindly copying that derived
state in another route graph can make Pydantic interpret field-specific metadata in
the wrong schema context. The failure was intermittent and became reproducible when
`UnsupportedFieldAttributeWarning` was promoted to an exception during repeated
parallel application construction.

The compatibility clone now deep-copies each function default and restores the
constructor-time values recorded by Pydantic's `_attributes_set`. Explicit aliases
such as `Idempotency-Key` remain intact, while FastAPI-derived implicit aliases and
annotations return to `None` before the new `APIRoute` is analyzed. Complete router
assembly is also protected by one reentrant lock so legacy route cloning and the
shared request-scoped pilot router cannot construct Pydantic schemas concurrently.

The release adds deterministic tests for default-state restoration and the assembly
serialization boundary, promotes the existing concurrent pilot test warning to an
error, and adds a standalone 12-round paired-application warning gate. Product
behavior, SQLite schema 46, and the 276 effective routes are unchanged.
