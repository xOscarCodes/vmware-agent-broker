# Validation and evidence

## Reproducible checks in this repository

For the 1.0.0 source snapshot, the Windows x86 build/test command completed with
warnings-as-errors and **297 tests passed**. The test runner reported that it made
no VMware calls, prompts or credential-store reads. Formatting verification and
both catalog checks passed in the local export workspace.

```powershell
.\build.ps1 -Test
dotnet format whitespace . --folder --include src tests --verify-no-changes
python .\coverage\check_catalog.py
python .\coverage\check_catalog.py --installed
```

`--installed` executes only the installed `vmrun` no-argument help and inspects
the pinned executable hashes and required VIX exports. It does not run VM commands.
CI cannot reproduce VMware guest operations without a separately provisioned and
authorized Workstation environment.

## Live-validation summary

The maintainer performed bounded local lab checks on disposable fixtures. This public
repository intentionally excludes private VM names, registration bindings, credential
metadata, host-specific paths, screenshots and raw live logs. Successful observed
areas include guest login/identity, typed public variables, generated fixture transfer,
helper existence/count/create/rename/owned-delete, an owned fixture process and focused
public text, snapshot/power operations, bounded full clone plus owned-clone deletion,
new-only shared folders, a host-only guest IP observation and a checksum-verified
Photon OVA download-only operation.

These are **limited observations of particular variants**, not 47 complete commands
or all installed flags passing. The tool's 47 source families are categorized as 9
implemented and 38 partial in this snapshot. Known live limits include:

- Global `list` can return a valid partial failure when a registered protected entry
  is stale or a deleted owned-clone tombstone remains. A separate valid single-target
  registration path was tested; those results are not interchangeable.
- `installTools` only requests/mounts the Tools installer image. It does not prove an
  MSI installation completed.
- The screen capture implementation is an MKS host-console equivalent. One visible
  lockscreen capture passed after opening/waking the console; this is not the
  guest-authenticated `vmrun captureScreen` behavior for every state.
- `runScriptInGuest` uses a bounded PowerShell command equivalent through native
  `RunProgram`; the original VIX `RunScript` carrier did not pass. Do not conflate
  those APIs.
- **Host port-forwarding add/delete were not positively validated.** The authorized
  temporary-mapping test did not complete a rule write. The original table was
  independently checked empty afterward; no forwarding success is claimed.
- Photon terms were reviewed/authorized before fetching. The downloaded OVA passed
  the pinned SHA-512 check, but was not imported, registered or booted.
- The public input test passed only in the owned fixture's own focused textbox. It
  is not arbitrary GUI/keyboard control.
- The 0.15.5 failed metadata snapshot test remains in history. The 0.15.6 fix passed
  an independent build, three additional full test runs, and a live guest revocation
  scenario with the corrected helper image.

Consult the command matrix for each route's narrower contract. Do not treat local
owner observations as CI guarantees. Private parent log files, VM identifiers and
credential-bearing registration metadata are intentionally not included in this repo.

## Evidence labels

- **Source state**: backend exists with the scope stated in the catalog.
- **Synthetic/local test**: unit, native-local, parser or fixture checks; no VMware
  guest operation implied.
- **Live scoped observation**: a named test fixture operation and bounded readback
  were performed; other variants remain untested.
- **ACK only / unknown / refusal**: not a verified success. Preserve the exact
  limitation and inspect state before any new request.
