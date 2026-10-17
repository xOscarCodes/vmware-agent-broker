using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace GuestBroker
{
    [DataContract]
    internal sealed class RegisteredName
    {
        [DataMember(Name = "name", IsRequired = true)] internal string Name { get; set; }
        [DataMember(Name = "registered", IsRequired = true)] internal bool Registered { get; set; }
    }
    // The control channel carries only this secret-free public result schema.
    // Deserialize, validate and reserialize; never forward raw native stdout/stderr.
    [DataContract]
    internal sealed class ResultData
    {
        [DataMember(Name = "ok", IsRequired = true)] internal bool Ok;
        [DataMember(Name = "target", EmitDefaultValue = false)] internal string Target;
        [DataMember(Name = "error", EmitDefaultValue = false)] internal string ErrorCode;
        [DataMember(Name = "stage", EmitDefaultValue = false)] internal string StageName;
        [DataMember(Name = "nativeExitCode", EmitDefaultValue = false)] internal string NativeExit;
        [DataMember(Name = "outcome", EmitDefaultValue = false)] internal string Outcome;
        [DataMember(Name = "nativeHostConnect", EmitDefaultValue = false)] internal bool? HostConnect { get; set; }
        [DataMember(Name = "architecture", EmitDefaultValue = false)] internal string Architecture { get; set; }
        [DataMember(Name = "hostApiVersionProperty", EmitDefaultValue = false)] internal int? ApiVersion { get; set; }
        [DataMember(Name = "guestAuthentication", EmitDefaultValue = false)] internal string Authentication { get; set; }
        [DataMember(Name = "registeredVMs", EmitDefaultValue = false)] internal List<RegisteredName> Registered { get; set; }
        [DataMember(Name = "powerState", EmitDefaultValue = false)] internal int? Power { get; set; }
        [DataMember(Name = "toolsState", EmitDefaultValue = false)] internal int? Tools { get; set; }
        [DataMember(Name = "credential", EmitDefaultValue = false)] internal string Credential { get; set; }
        [DataMember(Name = "registration", EmitDefaultValue = false)] internal string Registration { get; set; }
        [DataMember(Name = "toolsComputerName", EmitDefaultValue = false)] internal string Computer { get; set; }
        [DataMember(Name = "timezoneSetterExit", EmitDefaultValue = false)] internal int? TimezoneExit { get; set; }
        [DataMember(Name = "timezoneReadback", EmitDefaultValue = false)] internal string TimezoneReadback { get; set; }
        [DataMember(Name = "catalog", EmitDefaultValue = false)] internal List<CatalogEntry> CatalogRows { get; set; }
        [DataMember(Name = "catalogIndex", EmitDefaultValue = false)] internal List<CatalogIndexEntry> CatalogIndex { get; set; }
        [DataMember(Name = "operation", EmitDefaultValue = false)] internal OperationReport Operation { get; set; }
        [DataMember(Name = "policy", EmitDefaultValue = false)] internal string PolicySaved { get; set; }
        [DataMember(Name = "identityBaseline", EmitDefaultValue = false)] internal string IdentityBaseline { get; set; }
        [DataMember(Name = "identityRevision", EmitDefaultValue = false)] internal int? IdentityRevision { get; set; }
        [DataMember(Name = "registrationBinding", EmitDefaultValue = false)] internal string RegistrationBinding { get; set; }
        [DataMember(Name = "nativePropertyId", EmitDefaultValue = false)] internal int? NativePropertyId { get; set; }
        [DataMember(Name = "nativePropertyExpectedType", EmitDefaultValue = false)] internal string NativePropertyExpectedType { get; set; }
        [DataMember(Name = "nativePropertyActualType", EmitDefaultValue = false)] internal int? NativePropertyActualType { get; set; }
        [DataMember(Name = "setup", EmitDefaultValue = false)] internal string SetupSaved { get; set; }
        [DataMember(Name = "setupId", EmitDefaultValue = false)] internal string SetupId { get; set; }
        [DataMember(Name = "snapshotDigest", EmitDefaultValue = false)] internal string SnapshotDigest { get; set; }
        [DataMember(Name = "setupCount", EmitDefaultValue = false)] internal int? SetupCount { get; set; }
        [DataMember(Name = "setupProof", EmitDefaultValue = false)] internal string SetupProof { get; set; }
        [DataMember(Name = "guestUsernameForm", EmitDefaultValue = false)] internal string GuestUsernameForm { get; set; }

        internal static ResultData Error(string code, Stage stage)
        {
            return new ResultData { Ok = false, ErrorCode = code, StageName = Diagnostics.Name(stage), NativePropertyId = Diagnostics.FailedProperty, NativePropertyExpectedType = Diagnostics.FailedExpectedType, NativePropertyActualType = Diagnostics.FailedActualType, GuestUsernameForm = GuestUsernameNormalization.Form };
        }
        internal static ResultData Parse(string json)
        {
            if (json == null || json.Length > 32768) throw new BrokerError("worker_protocol_failed");
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                var result = (ResultData)new DataContractJsonSerializer(typeof(ResultData)).ReadObject(stream);
                result.Validate(); return result;
            }
        }
        internal string Json()
        {
            Validate();
            using (var stream = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(ResultData)).WriteObject(stream, this);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
        private static bool OneOf(string value, string choices) { return value == null || Array.IndexOf(choices.Split('|'), value) >= 0; }
        internal void Validate()
        {
            if (Target != null && !GuestBroker.Target.ValidName(Target)) throw new BrokerError("worker_protocol_failed");
            if (!OneOf(Architecture, "x86") || !OneOf(Authentication, "not_tested|not_attempted|succeeded") ||
                !OneOf(Credential, "stored|validated_not_stored|revoked") || !OneOf(Registration, "saved|removed") ||
                !OneOf(TimezoneReadback, "not_verified") || !OneOf(Outcome, "unknown")) throw new BrokerError("worker_protocol_failed");
            if (Computer != null) Policy.SafeHostname(Computer);
            if (Ok && GuestUsernameForm != null || !GuestUsernameNormalization.SafeForm(GuestUsernameForm)) throw new BrokerError("worker_protocol_failed");
            if (NativePropertyId.HasValue ? Ok || !Diagnostics.SafeProperty(NativePropertyId.Value) || !NativePropertyActualType.HasValue || NativePropertyExpectedType == null || !OneOf(NativePropertyExpectedType, "1|2|3|4|5|1_or_5") : NativePropertyExpectedType != null || NativePropertyActualType.HasValue) throw new BrokerError("worker_protocol_failed");
            if (StageName != null)
            {
                bool found = false; foreach (Stage stage in Enum.GetValues(typeof(Stage))) if (Diagnostics.Name(stage) == StageName) found = true;
                if (!found) throw new BrokerError("worker_protocol_failed");
            }
            if (NativeExit != null && (NativeExit.Length != 10 || !NativeExit.StartsWith("0x", StringComparison.Ordinal) || !GuestBroker.Target.Hex(NativeExit.Substring(2), 8))) throw new BrokerError("worker_protocol_failed");
            if (Registered != null)
            {
                if (Registered.Count > 64) throw new BrokerError("worker_protocol_failed");
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (RegisteredName item in Registered)
                    if (item == null || !item.Registered || !GuestBroker.Target.ValidName(item.Name) || !names.Add(item.Name)) throw new BrokerError("worker_protocol_failed");
            }
            if (CatalogRows != null)
            {
                if (CatalogRows.Count > 47) throw new BrokerError("worker_protocol_failed");
                var names = new HashSet<string>();
                foreach (CatalogEntry row in CatalogRows)
                {
                    CatalogEntry canonical = Catalog.Find(row.Name);
                    if (!names.Add(row.Name) || row.Syntax != canonical.Syntax || row.Gate != canonical.Gate || row.Backend != canonical.Backend || row.State != canonical.State || row.Guest != canonical.Guest || row.Risk != canonical.Risk || row.Exports != canonical.Exports || row.Accepted != canonical.Accepted || row.Synthetic != canonical.Synthetic || row.Live != canonical.Live)
                        throw new BrokerError("worker_protocol_failed");
                }
            }
            if (CatalogIndex != null)
            {
                if (CatalogIndex.Count != 47) throw new BrokerError("worker_protocol_failed"); var names = new HashSet<string>();
                foreach (CatalogIndexEntry row in CatalogIndex)
                {
                    if (row == null) throw new BrokerError("worker_protocol_failed"); CatalogEntry canonical = Catalog.Find(row.Name);
                    if (!names.Add(row.Name) || row.State != canonical.State || row.Backend != canonical.Backend || row.Guest != canonical.Guest) throw new BrokerError("worker_protocol_failed");
                }
            }
            if (Operation != null) Operation.Validate();
            if (PolicySaved != null && PolicySaved != "saved") throw new BrokerError("worker_protocol_failed");
            if (SetupSaved != null)
            {
                if (!Ok || !OneOf(SetupSaved, "clone_root|clone_registered|clone_finalized|network_baseline|forward_policy|photon_root") || (SetupSaved == "clone_registered" || SetupSaved == "clone_finalized" || SetupSaved == "forward_policy") != (SetupId != null) || SetupId != null && !GuestBroker.Target.Hex(SetupId, 32) || (SetupSaved == "network_baseline" || SetupSaved == "forward_policy") != (SnapshotDigest != null) || SnapshotDigest != null && !GuestBroker.Target.Hex(SnapshotDigest, 64) || (SetupSaved == "network_baseline") != SetupCount.HasValue || SetupCount < 0 || SetupCount > 256) throw new BrokerError("worker_protocol_failed");
            }
            else if (SetupId != null || SnapshotDigest != null || SetupCount.HasValue) throw new BrokerError("worker_protocol_failed");
            if (SetupSaved == "clone_finalized" ? SetupProof != "native_job_success_v1" : SetupProof != null) throw new BrokerError("worker_protocol_failed");
            if (IdentityBaseline != null ? IdentityBaseline != "path_uuid_v1" || Target == null || !IdentityRevision.HasValue || IdentityRevision < 1 || !GuestBroker.Target.Hex(RegistrationBinding, 64) : IdentityRevision.HasValue || RegistrationBinding != null) throw new BrokerError("worker_protocol_failed");
            if (Ok && ErrorCode != null) throw new BrokerError("worker_protocol_failed");
            int categories = (Registered != null ? 1 : 0) + (HostConnect.HasValue ? 1 : 0) + (Power.HasValue ? 1 : 0) +
                (Credential != null ? 1 : 0) + (Registration != null ? 1 : 0) + (Computer != null ? 1 : 0) + (TimezoneExit.HasValue ? 1 : 0) + (CatalogRows != null ? 1 : 0) + (CatalogIndex != null ? 1 : 0) + (Operation != null ? 1 : 0) + (PolicySaved != null ? 1 : 0) + (IdentityBaseline != null ? 1 : 0) + (SetupSaved != null ? 1 : 0);
            bool partial = !Ok && ErrorCode == "partial_vm_failure" && Operation != null && Operation.Command == "list" && Operation.Failures > 0;
            bool programFailed = !Ok && ErrorCode == "guest_program_failed" && Operation != null && (Operation.Command == "runProgramInGuest" || Operation.Command == "runScriptInGuest") && Operation.GuestExit.HasValue && Operation.GuestExit != 0;
            if ((Ok && categories != 1) || (!Ok && categories != 0 && !((partial || programFailed) && categories == 1))) throw new BrokerError("worker_protocol_failed");
            if (HostConnect.HasValue && (!HostConnect.Value || Architecture != "x86" || ApiVersion != -1 || Authentication != "not_tested")) throw new BrokerError("worker_protocol_failed");
            if (Power.HasValue != Tools.HasValue || (Power.HasValue && (Power < 0 || Tools < 0 || Authentication != "not_attempted"))) throw new BrokerError("worker_protocol_failed");
            if (Registered != null && Authentication != "not_attempted") throw new BrokerError("worker_protocol_failed");
            if (Computer != null && Authentication != "succeeded") throw new BrokerError("worker_protocol_failed");
            if (TimezoneExit.HasValue && (TimezoneExit != 0 || TimezoneReadback != "not_verified")) throw new BrokerError("worker_protocol_failed");
            if (!Ok && !AllowedError(ErrorCode)) throw new BrokerError("worker_protocol_failed");
        }
        internal static bool AllowedError(string code)
        {
            if (("|clone_copy_proof_required|clone_identity_refused|clone_identity_outcome_unknown|").Contains("|" + code + "|")) return true;
            if (("|host_policy_invalid|host_policy_busy|owned_clone_refused|owned_clone_backing_refused|clone_power_state_refused|owned_clone_outcome_unknown|forward_snapshot_invalid|forward_policy_required|forward_ownership_conflict|forward_scope_refused|forward_snapshot_changed|forward_outcome_unknown|photon_policy_required|photon_source_refused|photon_size_refused|photon_integrity_failed|photon_license_changed|photon_existing_license_required|photon_download_outcome_unknown|").Contains("|" + code + "|")) return true;
            if (code == "public_share_not_approved" || code == "public_share_foreign_mapping" || code == "public_share_outcome_unknown") return true;
            if (code == "transfer_policy_invalid" || code == "transfer_request_invalid" || code == "transfer_not_approved" || code == "transfer_source_refused" || code == "transfer_destination_exists" || code == "transfer_outcome_unknown") return true;
            if (code == "guest_fixture_listing_refused" || code == "protected_target_refused" || code == "guest_fixture_process_refused" || code == "guest_fixture_generated_refused" || code == "registration_refresh_unavailable") return true;
            if (code == null) return false;
            if (code.Length > 64 || code.Length == 0) return false;
            foreach (char c in code) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_') return false;
            if (code.StartsWith("vix_error_", StringComparison.Ordinal))
            {
                uint value; return UInt32.TryParse(code.Substring(10), out value) && value <= 65535;
            }
            if (("|catalog_invalid|catalog_operation_unavailable|unsupported_operation_option|secret_argument_forbidden|capability_policy_invalid|capability_policy_changed|capability_not_granted|disposable_target_required|program_not_approved|native_result_limit|snapshot_not_found|snapshot_name_ambiguous|partial_vm_failure|cli_plan_forbidden|unreviewed_cli_binary|cli_signature_untrusted|cli_start_failed|cli_status_failed|cli_isolation_unavailable|official_cli_failed|official_cli_timeout|cli_output_limit|cli_output_unrecognized|export_root_invalid|export_root_unavailable|export_root_not_approved|export_root_identity_changed|export_path_redirected|export_acl_rejected|export_destination_exists|private_export_limit|private_export_invalid|device_not_approved|device_identity_changed|script_not_approved|script_policy_invalid|script_identity_changed|script_size_rejected|script_encoding_rejected|share_not_approved|public_variable_policy_invalid|public_variable_not_granted|public_variable_value_rejected|guest_fixture_policy_invalid|guest_fixture_path_rejected|guest_fixture_root_changed|guest_fixture_not_approved|guest_fixture_image_unavailable|guest_fixture_helper_refused|guest_fixture_io_failed|guest_fixture_create_refused|guest_fixture_owned_refused|guest_fixture_delete_refused|guest_fixture_rename_refused|guest_fixture_not_empty|guest_fixture_mutation_uncertain|").Contains("|" + code + "|")) return true;
            return ("|invalid_request|invalid_deadline|local_operation_failed|user_cancelled|storage_not_approved|unknown_target|registration_changed|invalid_registration|duplicate_registration|corrupt_registry|registry_acl_rejected|registry_requires_local_fixed_volume|registry_limit_exceeded|registry_writer_unavailable|reparse_path_rejected|canonical_path_mismatch|vm_identity_changed_reenroll_required|vm_identity_unavailable|native_target_mismatch|invalid_pe|unsupported_architecture|unsupported_broker_architecture|secure_loader_unavailable|unreviewed_vix_binary|invalid_vix_size|vix_load_failed|loaded_module_mismatch|missing_vix_export|unexpected_vix_api_property|vix_signature_untrusted|invalid_vix_job|invalid_vix_result_handle|vix_property_type_mismatch|target_already_open|login_already_attempted|guest_program_failed|invalid_guest_identity|credential_size_rejected|empty_credential_rejected|credential_encoding_rejected|credential_prompt_failed|credential_prompt_invalid_parameter|credential_prompt_invalid_flags|credential_prompt_no_logon_session|credential_unpack_failed|credential_target_mismatch|credential_save_failed|credential_unavailable|credential_format_rejected|credential_delete_failed|native_worker_terminated|native_timeout|worker_protocol_failed|worker_start_failed|worker_status_failed|operation_cancelled|no_worker_result|").Contains("|" + code + "|");
        }
    }

    internal static class Output
    {
        internal const string Version = "VMware Agent Broker 1.0.0 (experimental, Windows .NET Framework x86)";
        internal const string Help = @"VMware Agent Broker 1.0.0 - policy-scoped local VMware Workstation operations
Per-operation approval prompts are DEFERRED. Configured requests execute unattended.
Target/capability/root/ownership/image/secret protections remain. This is not production security assurance.
Registration/policy/root setup and private credential entry/storage remain user-operated.
Use --stored for existing target-bound credentials; never -gu/-gp/password arguments.

Usage: guest-broker.exe <command> [--diagnostic] [--json]

  help | --help | -h             Show this help (also shown with no command)
  version | --version            Show build/runtime identity
  probe                         Check installed native VIX; no guest login
  catalog [command]             All 47 installed commands; support/gates/status
  policy <name>                 Private per-target capability/program review
  rebind-knownvm <name> --expect-binding <64-UPPERCASE-HEX>
                                Exact path/UUID refresh; preserve v2 key/policy/helper binding
  setup-clones <name> <scratch-parent> --expect-binding <HEX64>
  register-clone <source-name> <clone-ID32> <new-name>
  finalize-clone <source-name> <clone-ID32>
                                Actual native copied receipt ONLY; all prepared refuse;
                                offline empty-BIOS-UUID finalization, no replay/boot
  network-baseline <vmnet>       Read-only canonical NAT mapping snapshot digest
  setup-forwarding <vmnet> <HIGH-TCP-PORT> <private-IP> <guest-port> <snapshot-HEX64> <owner-scope-evidence-ID32>
  setup-photon <scratch-parent> [--existing-license-evidence <ID32> --license-sha256 <HEX64>]
                                Nonsecret setup only, no new license acceptance/approval UI
  vmrun <command> ...           Native / verified credential-free CLI subset
  list                          List registered names; no guest/vault access
  register                      Privately choose and approve ONE VMX in the UI
  status <name>                 Host/Tools state; authentication NOT attempted
  enroll <name> [--persist]      Private credential dialog; validate once
  identity <name> [--stored]     Authenticate; read Tools computer name
  timezone-melbourne <name> [--stored]
                                Fixed setter; configured disposable-VM timezone grant
  revoke <name>                 Delete ONLY that registration's saved credential
  unregister <name>             Confirm removal; revoke and remove registration

Names use exact registered spelling/case. No default VM, paths, all-VM selector,
password argument or unrestricted command passthrough. New mutations require
disposable-target policy and individual scoped grants; no per-operation approval UI.
--diagnostic: fixed, secret-free stage names on stderr; no native text/logs.
--json: machine-readable operational RESULTS (not help/version).
Optional output flags must be last; they may appear in either order, once each.

From utility root: .\bin\guest-broker.exe list
From bin:          .\guest-broker.exe status SAFE-DC

Enter guest credentials ONLY in the private Windows dialog.
Never paste passwords into chat, argv, environment, files or tool calls.
No automatic login retries.
See README.md and VALIDATION.md for boundaries, exit codes and troubleshooting.";

        internal static void Print(ResultData result, bool json)
        {
            Console.WriteLine(json ? result.Json() : Human(result));
        }
        internal static string Human(ResultData result)
        {
            return Wrap(HumanCore(result));
        }
        internal static string Wrap(string text)
        {
            var output = new StringBuilder();
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.TrimEnd('\r');
                while (line.Length > 80)
                {
                    int split = line.LastIndexOf(' ', 80);
                    if (split < 1) split = 80;
                    output.AppendLine(line.Substring(0, split)); line = line.Substring(split).TrimStart(' ');
                }
                output.AppendLine(line);
            }
            return output.ToString().TrimEnd();
        }
        private static string HumanCore(ResultData result)
        {
            result.Validate();
            var output = new StringBuilder();
            if (!result.Ok)
            {
                string label = result.ErrorCode == "user_cancelled" || result.ErrorCode == "operation_cancelled" ? "Cancelled" : "Error";
                output.Append(label);
                if (result.Target != null) output.Append(" [").Append(result.Target).Append(']');
                output.Append(": ").Append(result.ErrorCode).AppendLine();
                if (result.StageName != null) output.Append("Stage: ").Append(result.StageName).AppendLine();
                if (result.NativePropertyId.HasValue) output.AppendLine("Native property " + result.NativePropertyId + ": expected VIX type " + result.NativePropertyExpectedType + ", observed type " + result.NativePropertyActualType + ". Numeric type metadata only; no native error text.");
                if (result.NativeExit != null) output.Append("Worker exit: ").Append(result.NativeExit).AppendLine();
                if (result.NativeExit == "0xC0000005") output.AppendLine("Native access violation; this does NOT establish a password error.");
                if (result.ErrorCode == "native_timeout") output.AppendLine("Native deadline expired (exit 124). Do not retry automatically.");
                if (result.ErrorCode == "official_cli_timeout") output.AppendLine("Official CLI deadline expired (exit 124), not a successful IP/state observation. Returned CLI cause is distinct from the outer worker/native watchdog; no automatic retry.");
                if (result.Outcome == "unknown") output.AppendLine("Operation outcome UNKNOWN. Stop; coordinate before any retry.");
                if (result.ErrorCode == "user_cancelled") output.AppendLine("No success is claimed. Existing registration/credentials are not reset.");
                if (result.ErrorCode == "invalid_request") output.AppendLine("Use guest-broker.exe help. Submitted arguments are not echoed.");
                if (result.ErrorCode == "unknown_target") output.AppendLine("No exact registered name matched. Use list; names are case-sensitive.");
                if (result.ErrorCode == "vm_identity_changed_reenroll_required") output.AppendLine("Target identity changed. No old credential is used; review before re-registering.");
                if (result.ErrorCode == "credential_unavailable") output.AppendLine("No usable saved broker credential. Never paste credentials into this CLI.");
                if (result.ErrorCode == "vix_error_3034") output.AppendLine("Native interactive session absent (3034). No fallback login/unlock/forced session or focus.");
                if (result.ErrorCode == "vix_error_3035") output.AppendLine("Native interactive name match refused (3035), NOT proof of a different account or bad password. No fallback login/unlock/forced session or focus. No fallback login or password re-entry is requested.");
                if (result.GuestUsernameForm != null) output.AppendLine("Private interactive username shape/progress only: " + result.GuestUsernameForm + "; no account name, SID or password is exposed.");
                if (result.ErrorCode == "catalog_operation_unavailable") output.AppendLine("This command/variant is gated. Use catalog <command> for the precise gate.");
                if (result.ErrorCode == "disposable_target_required") output.AppendLine("New mutations require an explicitly disposable UNPROMOTED test VM policy.");
                if (result.ErrorCode == "capability_not_granted") output.AppendLine("This exact registration has not granted this command. No login was attempted.");
                if (result.Operation != null) AppendOperation(output, result.Operation);
                return output.ToString().TrimEnd();
            }
            if (result.SetupSaved != null)
            {
                output.AppendLine("Nonsecret setup: " + result.SetupSaved + ". No credential access or operation approval prompt.");
                if (result.SetupId != null) output.AppendLine("Public setup ID: " + result.SetupId);
                if (result.SnapshotDigest != null) output.AppendLine("Canonical mapping snapshot SHA256: " + result.SnapshotDigest);
                if (result.SetupCount.HasValue) output.AppendLine("Existing mapping count: " + result.SetupCount);
                if (result.SetupProof != null) output.AppendLine("Clone readiness proof: " + result.SetupProof + ". Offline configured BIOS UUID only; no boot/SMBIOS runtime or historical UNKNOWN upgrade to native job success.");
                if (result.SetupSaved == "photon_root") output.AppendLine("Official image license says downloading is assent. Only separately recorded EXISTING applicable terms permit image fetch; this setup accepts nothing new.");
                return output.ToString();
            }
            if (result.IdentityBaseline != null)
            {
                output.AppendLine("Registration baseline: exact canonical path/UUID mode; revision " + result.IdentityRevision + ". Physical VMX rewrites no longer rotate registration identity.");
                output.AppendLine("Binding preserved: " + result.RegistrationBinding + ". Saved credential key, per-target policy and helper binding unchanged. No vault/credential/native VM access performed.");
                return output.ToString();
            }
            if (result.CatalogIndex != null)
            {
                output.AppendLine("Installed vmrun catalog: 47 bounded backends; NOT full implementation/parity or all47 live PASS.");
                output.AppendLine("Operation approval: DEFERRED; configured scoped requests run unattended.");
                output.AppendLine("COMMAND                    STATE          BACKEND");
                foreach (CatalogIndexEntry item in result.CatalogIndex) output.AppendLine(item.Name.PadRight(27) + item.State.PadRight(15) + item.Backend);
                output.AppendLine("Use catalog <command> for exact scope, grammar and bounded live evidence.");
            }
            else if (result.CatalogRows != null)
            {
                output.AppendLine("Operation approval: DEFERRED; policy-scoped unattended execution. Risk labels and setup/credential prompts remain distinct.");
                if (result.CatalogRows.Count == 1)
                {
                    CatalogEntry item = result.CatalogRows[0];
                    output.AppendLine(item.Name + " - " + item.State + " / " + item.Backend);
                    output.AppendLine(item.Syntax); output.AppendLine("Accepted: " + item.Accepted);
                    output.AppendLine("Guest credentials: " + item.Guest + "; risk: " + item.Risk);
                    output.AppendLine("Gate/scope: " + item.Gate); output.AppendLine("Exports: " + item.Exports);
                    output.AppendLine("Synthetic: " + item.Synthetic); output.AppendLine("Live: " + item.Live);
                }
                else
                {
                    output.AppendLine("Installed vmrun catalog: 47 commands; NOT full implementation/parity.");
                    output.AppendLine("COMMAND                    STATE          BACKEND");
                    foreach (CatalogEntry item in result.CatalogRows) output.AppendLine(item.Name.PadRight(27) + item.State.PadRight(15) + item.Backend);
                    output.AppendLine("Use catalog <command> for exact grammar, modifier limits and gate.");
                }
            }
            else if (result.Operation != null) { if (result.Target != null) output.AppendLine("VM: " + result.Target); AppendOperation(output, result.Operation); }
            else if (result.PolicySaved != null) output.AppendLine("Policy saved for ONLY " + result.Target + ". No VM operation or credential access performed.");
            else if (result.Registered != null)
            {
                if (result.Registered.Count == 0) return "No VMs registered.\nRun guest-broker.exe register to privately approve one VM.\nGuest authentication: not attempted.";
                int width = 4; foreach (RegisteredName item in result.Registered) width = Math.Max(width, item.Name.Length);
                output.AppendLine("Registered VMs (registry only)");
                output.Append("NAME".PadRight(width)).AppendLine("  STATE");
                output.Append(new string('-', width)).AppendLine("  ----------");
                foreach (RegisteredName item in result.Registered) output.Append(item.Name.PadRight(width)).AppendLine("  Registered");
                output.AppendLine("Guest authentication: not attempted.");
            }
            else if (result.HostConnect.HasValue)
            {
                output.AppendLine("Native VIX support: local host connection succeeded.");
                output.AppendLine("Architecture: x86. DLL pin, signature and required exports checked.");
                output.Append("Host API property: ").Append(result.ApiVersion).AppendLine(" (requested-version sentinel).");
                output.AppendLine("Guest authentication: NOT TESTED.");
            }
            else
            {
                if (result.Target != null) output.Append("VM: ").AppendLine(result.Target);
                if (result.Power.HasValue)
                {
                    string power = (result.Power.Value & 8) != 0 ? "Powered on" : (result.Power.Value & 2) != 0 ? "Powered off" : "Other/unknown";
                    output.Append("Power: ").Append(power).Append(" (VIX ").Append(result.Power).AppendLine(").");
                    string tools = result.Tools == 2 ? "Running" : result.Tools == 4 ? "Not installed" : "Unknown";
                    output.Append("Tools: ").Append(tools).Append(" (VIX ").Append(result.Tools).AppendLine(").");
                    output.AppendLine("Host/Tools metadata only; guest authentication: NOT ATTEMPTED.");
                }
                if (result.Credential == "stored") output.AppendLine("Guest credential validated and saved for ONLY this registration.");
                if (result.Credential == "validated_not_stored") output.AppendLine("Guest credential validated. Not saved; owned transient buffers cleared.");
                if (result.Credential == "revoked") output.AppendLine("Only this registration's saved credential revoked (or already absent).");
                if (result.Registration == "saved") output.AppendLine("Registration saved. Run guest-broker.exe list for exact names.");
                if (result.Registration == "removed") output.AppendLine("Registration removed; its broker credential revoked.");
                if (result.Computer != null) output.Append("Guest authentication: succeeded.\nTools computer name: ").AppendLine(result.Computer);
                if (result.TimezoneExit.HasValue) output.AppendLine("Timezone setter exited 0. Final timezone readback NOT VERIFIED.");
            }
            return output.ToString().TrimEnd();
        }
        private static void AppendOperation(StringBuilder text, OperationReport report)
        {
            text.AppendLine("Command: " + report.Command + " / backend: " + report.Backend);
            text.AppendLine("Completion: " + report.Completion + "; guest authentication: " + report.Authentication);
            if (report.GuestExitPropertyType.HasValue) text.AppendLine("Native guest exit property 3018 observed type: " + report.GuestExitPropertyType + " (1=INTEGER/int32; 5=INT64). Read with that checked width.");
            if (report.ScriptCarrier != null) text.AppendLine("Script equivalent: native VixVM_RunProgramInGuest -> approved Windows PowerShell -NoProfile -NonInteractive -EncodedCommand. Pinned NONSECRET code only; no host subprocess, execution-policy override, temp-script/file-context guarantee or raw output. Not VixVM_RunScriptInGuest.");
            if (report.Count.HasValue) text.AppendLine("Bounded count: " + report.Count);
            if (report.Tools.HasValue) text.AppendLine("Native Tools metadata: " + report.Tools + " (not an official CLI readiness verdict).");
            if (report.ToolsObservation == "same_handle_wait_completed") text.AppendLine("Native WaitForToolsInGuest(30s) completed, then actual property152 was re-read on that SAME VM handle. No guest login or assumed healthy value.");
            if (report.ToolsObservation == "mount_only_request_ack") text.AppendLine("Mount-only request ACK: MOUNT0 | RETURN_IMMEDIATELY2; AUTO_UPGRADE1 NOT used. This is not completed Windows Tools installation, MSI approval or permission to replay a prior unknown request.");
            if (report.Computer != null) text.AppendLine("Tools computer name: " + report.Computer);
            if (report.Exists.HasValue) text.AppendLine("Guest fixture alias: " + report.Fixture + "; requested kind exists: " + (report.Exists.Value ? "yes" : "no") + ". Single metadata observation; no contents/listing returned.");
            if (report.FixtureAction != null) text.AppendLine("Guest explicitly approved owned-fixture action: " + report.FixtureAction + " / alias " + report.Fixture + ". Helper acknowledgment only; state NOT independently verified. Deletion destroys the WHOLE owned test object including test streams. No foreign-object authority or contents output.");
            if (report.FixtureProcessSlot != null) text.AppendLine("Owned idle fixture process slot: " + report.FixtureProcessSlot + "; retained process-handle authority only, no caller PID. Fixed self-image, local owner-only control, automatic expiry/revocation. No arbitrary guest process or stdout.");
            if (report.FixtureLaunchMode != null) text.AppendLine("Reserved PUBLIC GUI launcher requested native interactive login8 and RunProgram ACTIVATE_WINDOW2, waiting for checked launcher exit. ACK is NOT actual Session1/foreground/focus/input proof. Existing owned supervisor30s expiry remains.");
            if (report.FixtureGeneratedId != null) text.AppendLine("Generated PUBLIC fixture: " + report.FixtureGeneratedBytes + " bytes; public recipe ID " + report.FixtureGeneratedId + ". Created/verified in guest by helper ACK; NOT host/guest byte transfer or independent host readback. No payload output.");
            if (report.TransferId != null) text.AppendLine("PUBLIC transfer / alias " + report.Fixture + ": " + report.TransferBytes + " bytes; origin ID " + report.TransferId + ". Actual received bytes verified against generated recipe. Native VIX pathname semantics, trusted guest/same user; not an atomic sandbox. Unique private residues retained; no automatic cleanup/retry.");
            if (report.ShareName != null) text.AppendLine("Dedicated NEW public fixture share: " + report.ShareName + ". Sole exact mapping checked; native enable ACK is not guest mount, isolation or persistence verification. No existing user tree adopted.");
            if (report.CloneId != null) text.AppendLine("Owned NEW full-clone ID: " + report.CloneId + ". Full local backing/UUID/receipt checks, no source deletion or boot. Native VIX semantics, not adversarial attestation.");
            if (report.MappingId != null) text.AppendLine("Owned temporary TCP mapping ID: " + report.MappingId + ". Canonical before/after mapping snapshot checked; may listen on ALL host interfaces. Owner-scope evidence is NOT proof of isolation. Parent must remove within its authorized test interval; no automatic expiry cleanup or adapter/firewall changes.");
            if (report.PhotonId != null) text.AppendLine("Official Photon5 download ID: " + report.PhotonId + "; bytes " + report.DownloadBytes + ". Fixed SHA512/size/license verified; DOWNLOAD ONLY, no import/boot/account/network configuration/new legal acceptance.");
            if (report.FixtureFiles.HasValue) text.AppendLine("PUBLIC guest directory counts / alias " + report.Fixture + ": files " + report.FixtureFiles + ", directories " + report.FixtureDirectories + ". Immediate entries only, max64. No names, contents, sizes or timestamps returned. Bounded observation, NOT a snapshot or later access grant.");
            if (report.ApprovedEntries != null)
            {
                text.AppendLine("APPROVED PUBLIC fixture entries / root alias " + report.Fixture + ". Names/kinds below come from the enrolled HOST manifest, selected by a digest-bound guest observation. Max8; no raw guest names/content. NOT a snapshot or later access grant.");
                if (report.ApprovedEntries.Count == 0) text.AppendLine("No enrolled entries observed in the completed enumeration.");
                foreach (PublicFixtureEntry entry in report.ApprovedEntries) text.AppendLine(entry.Alias + " | " + entry.Name + " | " + entry.Kind);
            }
            if (report.Variable != null) text.AppendLine("PUBLIC runtime alias: " + report.Variable + " / " + report.VariableKind + " = " + (report.IntegerValue.HasValue ? report.IntegerValue.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : report.BooleanValue.Value ? "true" : "false") + (report.Command == "writeVariable" ? " (REQUEST ACK, not readback)." : " (single typed observation)."));
            if (report.Address != null) text.AppendLine("Guest IP observation: " + report.Address + ". No networking was enabled.");
            if (report.Device != null) text.AppendLine("Optical device request: " + report.Device + ". Final connection state NOT verified.");
            if (report.Artifact != null) text.AppendLine("Private export ID: " + report.Artifact + " / screen.png (" + report.ArtifactBytes + " bytes). Image header checked; image data NOT returned.");
            if (report.Inventory != null)
            {
                text.AppendLine("Bounded host inventory; private descriptions/raw output suppressed.");
                foreach (InventoryRow row in report.Inventory)
                    text.AppendLine(row.Name + "  " + row.Kind + (row.Address == null ? "" : "  " + row.HostPort + " -> " + row.Address + ":" + row.GuestPort));
                if (report.Inventory.Count == 0) text.AppendLine("Recognized empty inventory (not a network configuration change).");
            }
            if (report.GuestExit.HasValue) text.AppendLine("Guest process exit: " + report.GuestExit + ". Stdout/stderr NOT captured.");
            if (report.SnapshotRefs != null) foreach (string item in report.SnapshotRefs) text.AppendLine("Snapshot reference: " + item);
            if (report.Rows != null)
            {
                text.AppendLine("VM NAME                       POWER     TOOLS     ERROR");
                foreach (VmStateRow row in report.Rows) text.AppendLine(row.Target.PadRight(30) + (row.Power.HasValue ? row.Power.ToString() : "-").PadRight(10) + (row.Tools.HasValue ? row.Tools.ToString() : "-").PadRight(10) + (row.Error ?? "none"));
                text.AppendLine("Per-VM failures: " + report.Failures + ". Unregistered VMs are never queried.");
            }
            if (report.Completion == "native_completed_not_verified") text.AppendLine("Native request completed; resulting guest/VM state NOT independently verified.");
            if (report.Completion == "cli_completed_not_verified") text.AppendLine("Official CLI returned zero; requested VM state NOT independently verified.");
        }
    }
}
