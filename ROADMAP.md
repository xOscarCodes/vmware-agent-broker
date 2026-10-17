# Roadmap

The catalog distinguishes source support, limited live observations and vendor
variant parity. A command in the catalog is not automatically a passing test.

## Near term

1. **Close live-validation gaps.** Re-run the exact isolated case for the ordinary
   multi-registration list and complete a temporary port-forwarding add/remove only
   when the required elevated context and restoration checks can run. The owned
   public-input sink has a scoped live success; keep it distinct from general GUI
   control. Keep successes distinct from refusals, unknown outcomes and skipped tests.
2. **Clarify command variants.** Verify each accepted flag/backend variant against
   the installed Workstation version. In particular, distinguish request
   acknowledgement from independent state readback.
3. **Resolve known mismatches.** Document and investigate the VIX/CLI Tools metadata
   discrepancy and the ordinary global `list` partial result without changing
   protected registrations to make tests green.
4. **Make testing reproducible.** Keep CI limited to source, synthetic fixtures,
   catalog parsing and available Windows-native local checks. VMware live tests
   require explicit disposable infrastructure and should not depend on developer
   credentials or host networking.

## Follow-on

- Expand partial command variants only when installed-version semantics and
  postconditions are understood.
- Improve capture semantics beyond the current host-console equivalent where a
  reliable public API contract is established.
- Revisit portability beyond the currently pinned Workstation/VIX installation.
- Keep the AI-agent skill synchronized with CLI grammar, setup boundaries and
  evidence labels.

## Explicit non-goals unless separately designed

- Passing passwords through command lines or unattended answer files.
- Arbitrary host/guest file paths, scripts, process termination, or global input
  injection.
- Silently changing host firewall/adapters, exposing existing host trees, or
  mutating a real/domain-controller VM as a test convenience.
- Claiming sandboxing, VMware-internal credential safety, full vendor parity or
  production security approval from synthetic tests.
