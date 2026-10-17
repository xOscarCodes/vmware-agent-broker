---
name: vmware-guest-agent-broker
description: Use this skill whenever an AI agent needs to operate or test VMware Workstation guests through the local VMware Agent Broker (VMGuard), select a registered VM, inspect command support, configure per-target capability policy, use saved guest credentials, or run bounded guest/host commands. It covers safe CLI use, private credential handling, setup boundaries, live-evidence reporting and troubleshooting without password command-line flags.
---

# VMware Agent Broker skill

Use the broker CLI as the agent-facing interface to configured VMware Workstation
targets. First read the repository [`README.md`](../../README.md),
[`docs/COMMANDS.md`](../../docs/COMMANDS.md) and [`docs/VALIDATION.md`](../../docs/VALIDATION.md).

## Operating procedure

1. Run `guest-broker.exe list`; use only an exact registered name. Never guess a
   VMX path, use the first registered VM or invent a bulk selector.
2. Check `guest-broker.exe catalog <command>` and the command reference. A partial
   backend is not full support for every installed `vmrun` option.
3. Use `--stored` for a previously enrolled target credential where supported. If
   the credential is unavailable, stop for private enrollment; never pass passwords
   with `-gu`, `-gp`, `-vp`, environment, stdin, script or helper arguments.
4. Configured operations execute without a per-operation approval dialog. Existing
   target policy, identity, capability, root and helper-image constraints still
   apply. Setup and private credential entry/storage are separate operations.
5. For mutations, use only authorized disposable fixtures. Independently inspect
   post-state. After timeout/unknown outcome, inspect before any new invocation;
   never blindly replay a clone, delete or transfer.
6. Keep guest output, passwords, VMX secrets, VNC settings and screenshots out of
   logs and reports. Return only the broker's bounded result.

## Evidence language

- Unit/native-local tests are not VMware guest integration tests.
- A zero exit or request ACK is not automatically an independently verified
  postcondition.
- Record refusals, timeouts, partial lists and unknown outcomes as such.
- Forty-seven catalog families do not imply forty-seven successful live variants.

## Boundaries

- Do not mutate a real/promoted domain controller for a positive or negative test.
- VM policy does not authorize host-network writes or existing-folder exposure.
- The broker is not a same-user sandbox; VMware's internal credential handling is
  outside its audit boundary.
- Photon download is license-sensitive and download-only. Do not fetch until the
  applicable terms are authorized; do not import/boot unless separately requested.

See [`docs/COMMANDS.md`](../../docs/COMMANDS.md) for grammar and
[`docs/VALIDATION.md`](../../docs/VALIDATION.md) for bounded results and limitations.
