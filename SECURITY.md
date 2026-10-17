# Security policy

## Scope

VMGuard is experimental local lab software. It is designed to reduce accidental
credential and target crossover; it is **not a security boundary** against code
running as the same Windows user/administrator, a compromised hypervisor, or a
guest administrator.

The broker keeps guest passwords out of process arguments and routes authenticated
guest calls through native VIX. This repository does not audit VMware's internal
credential copies, transport, telemetry or logging. Do not infer a guarantee about
those internal mechanisms.

## Reporting

Please contact the repository owner privately through GitHub before publishing a
potential vulnerability. Use a minimal reproduction with synthetic or disposable
fixtures. Do not attach credentials, secret-bearing VMX files, crash dumps, guest
logs or unredacted live-test transcripts to a public issue.

## Safe test boundaries

- Never use a real or promoted domain controller for destructive tests.
- Never put guest passwords in command lines, environment variables, committed
  files, logs or bug reports.
- Host-network changes and public shared-folder exposure require their separate
  machine-scoped policies and explicit scope.
- A helper receipt, executable hash or successful native call does not attest a
  compromised guest or make the broker a sandbox.
