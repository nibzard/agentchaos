# acx-schemas

Strict contract schemas and a fail-closed validator for AgentChaos
resources.

- Schemas live in `../schemas/` (JSON Schema draft 2020-12).
- Valid synthetic fixtures live in `../fixtures/valid/`.
- Every object shape is closed: unknown fields fail validation.

Install for development:

```bash
pip install -e '.[test]'
pytest
```

Usage:

```python
from acx_schemas import validate

validate(instance, "Effect")  # raises ContractViolation on any mismatch
```
