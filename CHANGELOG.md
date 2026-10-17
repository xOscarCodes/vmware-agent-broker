# Changelog

## 1.0.0 — 2026-10-18 (experimental)

- First public release and binary packaging of the VMware Agent Broker (VMGuard).
- Catalogs 47 installed `vmrun` command families with bounded implementations.
- Uses target-bound native VIX for guest credentials; configured operations run
  without per-operation approval dialogs.
- Includes an AI-agent skill, an Archify architecture diagram, command reference,
  security notes and prioritized roadmap.
- Experimental, Windows-only. Nine catalog entries are marked implemented and 38
  partial; not all command variants have complete live-test coverage.

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for tested scope and limitations.
