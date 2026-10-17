# Command catalog

The broker catalogs all 47 command names from the pinned installed `vmrun` version. The matrix describes **bounded source backends**, not universal option parity or successful live operations. `coverage/check_catalog.py --installed` compares the catalog with the installed no-argument `vmrun` help; private live logs are not published.

| Command | Bounded syntax | Backend | Source state | Scope summary |
|---|---|---|---|---|
| `start` | `vmrun start <vm> gui\|nogui` | native-vix | implemented | gui,nogui; explicit mode |
| `stop` | `vmrun stop <vm> hard\|soft` | native-vix | implemented | hard,soft; explicit mode required |
| `reset` | `vmrun reset <vm> hard\|soft` | native-vix | implemented | hard,soft; explicit mode required |
| `suspend` | `vmrun suspend <vm> hard\|soft` | native-vix | implemented | hard,soft; explicit mode required |
| `pause` | `vmrun pause <vm>` | native-vix | implemented | no options |
| `unpause` | `vmrun unpause <vm>` | native-vix | implemented | no options |
| `listSnapshots` | `vmrun listSnapshots <vm> [showTree]` | native-vix | partial | showTree; counts and opaque tree refs only, no raw names/descriptions |
| `snapshot` | `vmrun snapshot <vm> <label>` | native-vix | implemented | one bounded non-secret snapshot label |
| `deleteSnapshot` | `vmrun deleteSnapshot <vm> <label> [andDeleteChildren]` | native-vix | implemented | andDeleteChildren; duplicate names fail closed |
| `revertToSnapshot` | `vmrun revertToSnapshot <vm> <label>` | native-vix | implemented | one unique snapshot label |
| `listHostNetworks` | `vmrun listHostNetworks` | official-vmrun-cli | partial | fixed local READ scope; strict six columns with unique canonical nonnegative Int32 identifiers, no ordinal/order/name relation; name/kind only |
| `listPortForwardings` | `vmrun listPortForwardings <network>` | official-vmrun-cli | partial | vmnet0..vmnet999 only; bounded protocol/port/IP rows, no descriptions |
| `setPortForwarding` | `vmrun setPortForwarding <vmnet> tcp <49152..65535> <private-IPv4> <guest-port> [broker-temporary-ID32]` | official-vmrun-cli | partial | one preconfigured machine-bound temporary TCP mapping on existing NAT; exact tuple/unused port/original snapshot/computed own description |
| `deletePortForwarding` | `vmrun deletePortForwarding <vmnet> tcp <owned-high-port>` | official-vmrun-cli | partial | only exact new owned mapping with full original-plus-owned snapshot, no wildcard/existing-rule adoption |
| `runProgramInGuest` | `vmrun runProgramInGuest <vm> <program-alias> [--stored] -- [non-secret-arg ...]` | native-vix | partial | generic waiting aliases flags0/login0 unchanged. ONLY reserved BROKER_PUBLIC_FIXTURE requests interactive8/ACTIVATE2/checked exit;15.8 privately canonicalizes ONLY dot-local username using one original0 guest-COMPUTERNAME/logout preflight before8, never fallback/variant retries |
| `fileExistsInGuest` | `vmrun fileExistsInGuest <vm> <guest-root-alias> <nonsecret-relative-path> [--stored]` | native-vix-helper | partial | typed existence via current helper or exact compatible frozen3 basic ABI; no absolute path/contents/auto bootstrap |
| `directoryExistsInGuest` | `vmrun directoryExistsInGuest <vm> <guest-root-alias> <nonsecret-relative-path> [--stored]` | native-vix-helper | partial | same manually bootstrapped handle-bound root helper; bool observation only; missing/access/redirect failures are distinct |
| `setSharedFolderState` | `vmrun setSharedFolderState <vm> <public-share-name> writable\|readonly` | native-vix | partial | only NEW public fixture folder, sole exact mapping; no caller path |
| `addSharedFolder` | `vmrun addSharedFolder <vm> <public-share-name>` | native-vix | partial | only NEW setup-created public host fixture folder; generated1024-byte file; add READONLY; no existing mappings |
| `removeSharedFolder` | `vmrun removeSharedFolder <vm> <approved-share>` | official-vmrun-cli | partial | exact separate name grant; remove access, never host file deletion |
| `enableSharedFolders` | `vmrun enableSharedFolders <vm>` | native-vix | partial | native option0 only with sole exact owned public mapping; no runtime modifier |
| `disableSharedFolders` | `vmrun disableSharedFolders <vm> [runtime]` | official-vmrun-cli | partial | default or runtime-only disable; no host path deletion |
| `listProcessesInGuest` | `vmrun listProcessesInGuest <vm> [--stored]` | native-vix | partial | count only; no owners/command lines/PIDs |
| `killProcessInGuest` | `vmrun killProcessInGuest <vm> <root-alias> <slot1..slot4> [--stored]` | native-vix-helper | partial | fixed broker-launched public fixture only; retained original process handle, no caller PID/program; reject-remote local control |
| `runScriptInGuest` | `vmrun runScriptInGuest <vm> <private-script-alias> [--stored]` | native-vix | partial | PowerShell command-equivalent via native RunProgram, NOT RunScript API: pinned NONSECRET UTF8<=16KiB plus encoded commandline bound, UTF16LE, fixed NoProfile/NonInteractive |
| `deleteFileInGuest` | `vmrun deleteFileInGuest <vm> <root-alias> <owned-relative-file> [--stored]` | native-vix-helper | partial | WHOLE helper-created test-object deletion INCLUDING test streams/content, exact ledger/private/single-link/no-follow handle; no foreign data |
| `createDirectoryInGuest` | `vmrun createDirectoryInGuest <vm> <root-alias> <new-relative> [--stored]` | native-vix-helper | partial | atomic handle-relative FILE_CREATE private empty directory; existing name refused, parents must already exist; maximum 64 creations per enrollment |
| `deleteDirectoryInGuest` | `vmrun deleteDirectoryInGuest <vm> <root-alias> <owned-relative-directory> [--stored]` | native-vix-helper | partial | WHOLE owned test tree+streams max64, preflight every descendant against helper ledger/private IDs; foreign/linked/reparse children refuse |
| `CreateTempfileInGuest` | `vmrun CreateTempfileInGuest <vm> <root-alias> <new-relative> [--generated 1..1048576] [--stored]` | native-vix-helper | partial | EMPTY default or separately granted fixed PUBLIC generated recipe <=1MiB; CreateNew/no imports/overwrite; max64 creation/tombstones; not vendor temp selection or byte transfer |
| `listDirectoryInGuest` | `vmrun listDirectoryInGuest <vm> <root-alias> <public-relative-directory> [--approved] [--stored]` | native-vix-helper | partial | partial: default max64 COUNTS ONLY; --approved max8 host+guest enrolled names/kinds with digest-bound presence bitmap; no raw guest names/content/recursion; mismatches refuse |
| `CopyFileFromHostToGuest` | `vmrun CopyFileFromHostToGuest <vm> <transfer-alias> <1..1048576> [--stored]` | native-vix | partial | GENERATED PUBLIC <=1MiB only; fresh guest filename, actual native roundtrip receive verification; no arbitrary paths/helper |
| `CopyFileFromGuestToHost` | `vmrun CopyFileFromGuestToHost <vm> <transfer-alias> <PUBLIC-ID32> <1..1048576> [--stored]` | native-vix | partial | own target/root-bound prior generated-origin ID only; computed guest filename, actual bytes into NEW private receive with recipe verification |
| `renameFileInGuest` | `vmrun renameFileInGuest <vm> <root-alias> <owned-relative-file> <new-basename> [--stored]` | native-vix-helper | partial | same-parent owned file-ID rename, zero primary/private/single-link, streams preserved, no replacement/directory/cross-parent move |
| `typeKeystrokesInGuest` | `vmrun typeKeystrokesInGuest <vm> <root-alias> <slot1..slot4> PUBLIC_ALNUM [--stored]` | native-vix-helper | partial | fixed PUBLIC sample only into exact owned focused form, no arbitrary text/keys/global input/clipboard/foreign HWND |
| `connectNamedDevice` | `vmrun connectNamedDevice <vm> <optical-id>` | official-vmrun-cli | partial | exact enrolled SATA/SCSI/IDE cdrom-image device and pinned ISO only; NO NIC/disk/USB/raw drive |
| `disconnectNamedDevice` | `vmrun disconnectNamedDevice <vm> <optical-id>` | official-vmrun-cli | partial | same exact ISO-backed optical-device allowlist; no generic device dispatch |
| `captureScreen` | `vmrun captureScreen <vm>` | official-vmcli-cli | partial | PRIVATE HOST-CONSOLE vmcli MKS equivalent, NOT native guest capture; no caller path |
| `writeVariable` | `vmrun writeVariable <vm> guestVar <public-alias> <int32-or-bool>` | native-vix | partial | own computed public runtime keys; canonical int32/bool, exact alias bounds/write grant; no strings/custom keys/env/config |
| `readVariable` | `vmrun readVariable <vm> guestEnv COMPUTERNAME [--stored] OR guestVar <public-alias>` | native-vix | partial | legacy hostname authenticates; typed own public aliases do not retrieve credentials and refuse --stored; no arbitrary strings |
| `getGuestIPAddress` | `vmrun getGuestIPAddress <vm> [-wait]` | official-vmrun-cli | partial | credential-free fixed CLI, strict literal IP only,30s CLI deadline; outer watchdog remains distinct |
| `list` | `vmrun list` | native-vix | partial | registered-VM power metadata only, per-VM errors; not a host-wide discovery scan |
| `upgradevm` | `vmrun upgradevm <vm>` | official-vmrun-cli | partial | exact signed/hash-pinned credential-free CLI, no native VM session/options |
| `installTools` | `vmrun installTools <vm>` | native-vix | partial | native MOUNT0\|RETURN_IMMEDIATELY2 only, NEVER AUTO_UPGRADE1; ACK not Windows installation |
| `checkToolsState` | `vmrun checkToolsState <vm>` | native-vix | partial | native on/not-paused/nonrunning -> WaitForToolsInGuest30 then actual SAME-handle property152 requery; never assumed healthy |
| `deleteVM` | `vmrun deleteVM <owned-clone-name>` | native-vix | partial | only stopped NEW full clone separately registered with own native completion/root/backing/UUID receipt; native Delete2 |
| `clone` | `vmrun clone <source-name> full` | native-vix | partial | stopped disposable source -> NEW child; native full0/snapshot0; EMPTY BIOS identity only with actual native completion proof; no boot/linked/source overwrite |
| `downloadPhotonVM` | `vmrun downloadPhotonVM photon5` | official-https | partial | DOWNLOAD ONLY fixed official packages.broadcom.com Photon5 x86_64 hw15 OVA into NEW scratch; same pinned SHA512/256..400MiB/EULA; no redirects/caller URL/auth/proxy/cookies/cert bypass/import/boot/account/network configuration |

## Risk and data notes

- Guest credentials are target-bound and passed through native VIX, never VMware CLI password flags.
- Guest helper filesystem operations require an exact helper receipt and explicit public fixture policy; normal VIX path operations are not an adversarial filesystem sandbox.
- Host networking writes use separate machine-scoped policy. The catalog entry does not authorize a real exposure or imply a firewall rule.
- `captureScreen` is a private MKS host-console equivalent, not the authenticated guest `vmrun captureScreen` behavior.
- `runScriptInGuest` currently uses a pinned PowerShell command-equivalent carrier; it is not evidence that the installed VIX RunScript temporary-file semantics work.
- Photon download is fixed-origin, license-gated and download-only; it does not import or boot a VM.

See [validation](VALIDATION.md), [security](../SECURITY.md), and the [roadmap](../ROADMAP.md).
