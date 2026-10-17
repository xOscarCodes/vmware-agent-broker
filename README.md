# VMware Agent Broker

**VMGuard** is a local Windows CLI broker for AI agents and automation that need
bounded access to VMware Workstation guests. It keeps VMware guest credentials out
of process arguments while routing credentialed guest operations through the
installed native VIX API.

> **Status:** experimental, Windows-only lab software. The catalog covers all 47
> command names in the pinned `vmrun` version, but support is intentionally bounded:
> partial backends are not full vendor parity, and local tests are not live VM tests.
> Read [validation status](docs/VALIDATION.md) and the
> [capability catalog](docs/COMMANDS.md) before use.

## Architecture

[Open the interactive architecture diagram](docs/architecture.html) ·
[View the Archify specification](docs/architecture.json)

The CLI resolves one explicitly registered target. Authenticated guest operations
use native VIX and a target-bound credential. Fixed, signed, hash-pinned VMware CLI
plans form a separate credential-free path. Optional guest helpers require an exact
image, enrollment and fixture root.

## Security model

- **Never put a password in CLI arguments, environment variables, standard input,
  scripts, logs, helper arguments or agent messages.** VMware `-gu`, `-gp` and `-vp`
  credential flags are not accepted by this broker.
- Credentialed guest calls use the selected registration's saved credential or a
  private Windows credential prompt and authenticate through native VIX.
- VM names resolve to one explicit registration. There is no implicit default VM,
  arbitrary caller VMX path or bulk mutation selector.
- This export uses the reserved name `SAFE-DC` as a compile-time protected-target
  example. It is **not automatic domain-controller detection**. Review/customize this
  guard for the names in your own environment before using the tool.
- Configured scoped operations run without a per-operation approval dialog. Target
  policy and setup boundaries still apply; private registration, credential
  enrollment/storage and capability configuration are separate setup operations.
- Fixture transfers use generated non-secret content. Shared-folder exposure uses a
  newly created dedicated fixture. Host networking writes have a separate
  machine-scoped policy.
- This is **not a security sandbox** against the same Windows user, administrator,
  a compromised hypervisor or a guest administrator. VMware's internal credential
  transport is outside this project's audit boundary.

See [SECURITY.md](SECURITY.md) for threat boundaries and reporting guidance.

## Requirements

- Windows with VMware Workstation and its **32-bit VIX library** installed.
- The broker pins the supported VMware executables and VIX library hashes in
  `coverage/vmrun-coverage.json`; another installation may be rejected until
  explicitly reviewed.
- Windows .NET Framework x86 C# compiler (`%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe`)
  and PowerShell for the build. The build uses framework assemblies and adds no
  NuGet packages or machine-wide software.
- VMware Tools in guests that need authenticated guest operations.

This is a C# x86 utility. It is not the Rust product application and does not expose
a service, network listener or MCP endpoint.

## Build and verify

From the repository root in Windows PowerShell:

```powershell
.\build.ps1 -Test
python .\coverage\check_catalog.py
python .\coverage\check_catalog.py --installed
```

The first command builds the broker, guest helper and tests with warnings treated as
errors. The tests include synthetic and local filesystem/process cases; they do not
run VMware guest operations. The default catalog check validates the 47-command
catalog. `--installed` executes only the installed `vmrun` no-argument help and
checks executable pins and public VIX exports; it runs no VM command.

## Quick start

```powershell
.\build.ps1
Set-Location .\bin
.\guest-broker.exe help
.\guest-broker.exe list
.\guest-broker.exe register
.\guest-broker.exe policy <registered-name>
```

Registration privately selects one VM. Configure its capability policy, then enroll
guest credentials privately. For a previously saved credential:

```powershell
.\guest-broker.exe enroll <registered-name> --persist
.\guest-broker.exe identity <registered-name> --stored
.\guest-broker.exe vmrun checkToolsState <registered-name> --diagnostic
```

`--persist` still requires explicit consent in the private credential prompt. Never
include a password in these command lines. A clone does not inherit the source
registration's credential.

Plain, human-readable output is the default. Use `--json` for the bounded result and
`--diagnostic` for fixed, secret-free stage names. See the
[47-command reference](docs/COMMANDS.md).

## Support and roadmap

The source catalog provides a bounded backend for each of the 47 installed command
families. In this snapshot, 9 are marked implemented and 38 partial. **This does not
mean every `vmrun` option is supported or all 47 have successful live tests.** Some
operations have only scoped or limited observations, and several scenarios remain
blocked or require a particular test fixture. See [docs/VALIDATION.md](docs/VALIDATION.md).

### Roadmap

1. Complete the remaining scoped live-validation gaps, especially the ordinary
   multi-registration list and machine-scoped port-forwarding restoration.
2. Verify more installed command flags and postconditions instead of treating a
   bounded backend or request ACK as full parity.
3. Clarify VMware Tools install-vs-mount and native `RunScript`-vs-PowerShell
   equivalent semantics.
4. Add reproducible Windows CI and review portability beyond the currently pinned
   Workstation/VIX installation.

See [ROADMAP.md](ROADMAP.md) for the prioritized details and explicit non-goals.
AI agents should read the [bundled skill](skills/vmware-guest-agent-broker/SKILL.md)
before operating the tool.

## License

Apache-2.0. VMware Workstation and its VIX library are separate vendor products;
this repository does not redistribute those binaries. See [LICENSE](LICENSE).
