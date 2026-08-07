# Concurrent router schema isolation

VulnFlow 72.0.71 closes a compatibility boundary in the remaining legacy router
cloning path. FastAPI mutates parameter `FieldInfo` objects while it analyzes an
`APIRoute`; imported template endpoints therefore no longer contain pristine
constructor defaults. A secondary application must not reuse those mutated objects.

`app.router_cloning._clone_parameter_value()` deep-copies each positional and
keyword-only default. When the object exposes Pydantic `_attributes_set`, the clone
restores constructor-time `alias`, `validation_alias`, `serialization_alias`, and
`annotation` values. This preserves explicitly configured aliases while removing
state derived by the template route's first analysis.

`app.routers.install_routers()` protects the complete router graph assembly with a
reentrant lock. The boundary includes legacy route cloning, dependency installation,
route transfer, and public inclusion of the shared pilot DI router. Runtime requests
remain concurrent; only application schema construction is serialized.

Acceptance requires:

- implicit parameter aliases and annotations are reset before clone analysis;
- explicit aliases such as `Idempotency-Key` are preserved;
- two concurrent application builds retain 276 effective routes each;
- `UnsupportedFieldAttributeWarning` is treated as an error;
- twelve paired build/release rounds complete without the warning;
- existing pilot request isolation and lifecycle release contracts remain green.
