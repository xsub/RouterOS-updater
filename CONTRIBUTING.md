# Contributing

Install dependencies and development tools as described in README.md, then run:

```sh
python -m pytest -q -W error
ruff check src tests tools
ruff format --check src tests tools
python tools/check_public_tree.py
python -m build --no-isolation
pip-audit -r requirements.lock --require-hashes --strict
```

Use synthetic fixtures, documentation domains and fictional private addresses.
Generate temporary SSH keys in tests. Keep device identifiers, host keys,
credentials, exports, packet captures, raw reports and environment dumps outside
the repository.

Preserve recovery invariants. Add regression tests for changes to restart
evidence, backup durability, identity checks, version policy and ambiguous command
outcomes. Hardware-specific validation claims need actual test evidence.
