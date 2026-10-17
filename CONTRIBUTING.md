# Contributing

Thanks for improving VMGuard. Keep changes narrow and align each claim with evidence.

## Before changing code

1. Read the affected command entry in `docs/COMMANDS.md`, the architecture diagram
   and `docs/VALIDATION.md`.
2. Preserve target binding, no-password-CLI behavior and helper/credential
   compatibility. Never substitute a VMware CLI password flag for native VIX.
3. Use new synthetic or disposable fixtures. Do not commit VMX files, credentials,
   machine-specific IDs, live screenshots, host configuration or test logs.
4. Keep output bounded and secret-free. A mock/native-local test is not a VMware
   live test; an operation ACK is not independent state readback.

## Checks

```powershell
.\build.ps1 -Test
dotnet format whitespace . --folder --include src tests --verify-no-changes
python .\coverage\check_catalog.py
python .\coverage\check_catalog.py --installed
```

The installed check requires the pinned VMware installation. If it cannot run, report
it as skipped rather than claiming it passed.

## Pull requests

Describe affected command variants, credential path, target/root scope and failure
semantics. Include success, refusal and unknown-outcome tests. Sanitize any live
evidence and never attach passwords, VNC keys or raw configuration.
