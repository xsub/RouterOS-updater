# Validation

Version 0.1.1 local verification:

- 116 tests passed on Python 3.11 and Python 3.12 with warnings treated as errors.
- SSH/SFTP tests used a loopback server and ephemeral keys.
- Ruff lint and formatting checks passed.
- Both shell deployment scripts passed syntax checks.
- Wheel and source distribution builds succeeded.
- Publication checks inspect the tracked source boundary for private files,
  machine-local paths and common credential patterns.

The runtime dependency lock was audited without reported known vulnerabilities.
This is not a security guarantee or independent audit of the application.

No real router was updated or restarted. The full RouterOS CLI contract, hardware
update/restore cycle and live Linux systemd behavior still require validation.
CI results are recorded by GitHub Actions.
