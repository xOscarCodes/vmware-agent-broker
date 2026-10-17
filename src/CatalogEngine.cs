using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace GuestBroker
{
    [DataContract]
    internal sealed class VmStateRow
    {
        [DataMember(IsRequired = true)] internal string Target { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? Power { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? Tools { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Error { get; set; }
    }
    [DataContract]
    internal sealed class InventoryRow
    {
        [DataMember(IsRequired = true)] internal string Name { get; set; }
        [DataMember(IsRequired = true)] internal string Kind { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? HostPort { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? GuestPort { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Address { get; set; }
    }
    [DataContract]
    internal sealed class OperationReport
    {
        [DataMember(IsRequired = true)] internal string Command { get; set; }
        [DataMember(IsRequired = true)] internal string Backend { get; set; }
        [DataMember(IsRequired = true)] internal string Completion { get; set; }
        [DataMember(IsRequired = true)] internal string Authentication { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? Count { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<string> SnapshotRefs { get; set; }
        [DataMember(EmitDefaultValue = false)] internal long? GuestExit { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Computer { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? Tools { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<VmStateRow> Rows { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int Failures { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Address { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<InventoryRow> Inventory { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Artifact { get; set; }
        [DataMember(EmitDefaultValue = false)] internal long? ArtifactBytes { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Device { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Variable { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string VariableKind { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? IntegerValue { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool? BooleanValue { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string Fixture { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool? Exists { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string FixtureAction { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? FixtureFiles { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? FixtureDirectories { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<PublicFixtureEntry> ApprovedEntries { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string FixtureProcessSlot { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string FixtureGeneratedId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? FixtureGeneratedBytes { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string TransferId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? TransferBytes { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string ShareName { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int? GuestExitPropertyType { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string ScriptCarrier { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string ToolsObservation { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string FixtureLaunchMode { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string CloneId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string MappingId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string PhotonId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal long? DownloadBytes { get; set; }
        internal void Validate()
        {
            CatalogEntry entry = Catalog.Find(Command);
            if (Command == "runScriptInGuest" ? ScriptCarrier != PinnedScript.Carrier : ScriptCarrier != null) throw new BrokerError("worker_protocol_failed");
            if (ToolsObservation != null && (Command == "checkToolsState" ? !Tools.HasValue || ToolsObservation != "same_handle_wait_completed" && ToolsObservation != "immediate_property" : Command != "installTools" || ToolsObservation != "mount_only_request_ack")) throw new BrokerError("worker_protocol_failed");
            if (!entry.Enabled || Backend != entry.Backend || (Completion != "metadata_only" && Completion != "native_completed_not_verified" && Completion != "partial_failure" && Completion != "bounded_cli_observation" && Completion != "cli_completed_not_verified" && Completion != "private_export_header_checked" && Completion != "guest_fixture_observation" && Completion != "guest_fixture_mutation_ack" && Completion != "guest_fixture_listing_observation" && Completion != "guest_fixture_approved_listing_observation" && Completion != "guest_fixture_process_ack" && Completion != "public_transfer_roundtrip_verified" && Completion != "public_transfer_received_verified" && Completion != "public_share_mapping_verified" && Completion != "owned_full_clone_created" && Completion != "owned_clone_deleted" && Completion != "owned_forward_added" && Completion != "owned_forward_restored" && Completion != "official_photon_image_verified") ||
                Authentication != (Variable != null ? "not_attempted" : entry.NeedsCredential ? "succeeded" : entry.Guest == "depends" ? "succeeded" : "not_attempted") || Count < 0 || Count > 256 || Failures < 0 || Failures > 64)
                throw new BrokerError("worker_protocol_failed");
            bool fixtureProbe = Command == "fileExistsInGuest" || Command == "directoryExistsInGuest";
            bool fixtureMutation = GuestFixture.Mutation(Command);
            bool fixtureListing = GuestFixture.Listing(Command);
            bool fixtureProcess = FixtureProcessSlot != null;
            if (fixtureProcess && Command == "runProgramInGuest" ? FixtureLaunchMode != NativePlans.FixtureLaunchMode : FixtureLaunchMode != null) throw new BrokerError("worker_protocol_failed");
            bool generated = FixtureGeneratedId != null || FixtureGeneratedBytes.HasValue;
            bool transfer = PublicTransfers.Command(Command);
            if ((CloneId != null || MappingId != null || PhotonId != null) && (Count.HasValue || SnapshotRefs != null || GuestExit.HasValue || Computer != null || Tools.HasValue || Rows != null || Failures != 0 || Address != null || Inventory != null || Artifact != null || ArtifactBytes.HasValue || Device != null || Variable != null || Fixture != null || FixtureAction != null || FixtureProcessSlot != null || generated)) throw new BrokerError("worker_protocol_failed");
            if (Command == "clone" || Command == "deleteVM" ? !Target.Hex(CloneId, 32) || Completion != (Command == "clone" ? "owned_full_clone_created" : "owned_clone_deleted") : CloneId != null || Completion == "owned_full_clone_created" || Completion == "owned_clone_deleted") throw new BrokerError("worker_protocol_failed");
            if (OwnedForwarding.Command(Command) ? !Target.Hex(MappingId, 32) || Completion != (Command == "setPortForwarding" ? "owned_forward_added" : "owned_forward_restored") : MappingId != null || Completion == "owned_forward_added" || Completion == "owned_forward_restored") throw new BrokerError("worker_protocol_failed");
            if (Command == "downloadPhotonVM" ? !Target.Hex(PhotonId, 32) || !DownloadBytes.HasValue || DownloadBytes < PhotonDownload.Minimum || DownloadBytes > PhotonDownload.Maximum || Completion != "official_photon_image_verified" : PhotonId != null || DownloadBytes.HasValue || Completion == "official_photon_image_verified") throw new BrokerError("worker_protocol_failed");
            if (GuestExitPropertyType.HasValue && ((GuestExitPropertyType != 1 && GuestExitPropertyType != 5) || (Command != "runProgramInGuest" && Command != "runScriptInGuest" && !GuestFixture.Command(Command)))) throw new BrokerError("worker_protocol_failed");
            if (PublicSharing.Command(Command) ? !FixtureProtocol.Alias(ShareName) || Completion != (Command == "enableSharedFolders" ? "native_completed_not_verified" : "public_share_mapping_verified") || Count.HasValue || Rows != null || Computer != null || Tools.HasValue || Artifact != null || Address != null || Device != null || Variable != null || generated || fixtureProcess || Fixture != null : ShareName != null || Completion == "public_share_mapping_verified") throw new BrokerError("worker_protocol_failed");
            if (transfer ? !FixtureProtocol.Hex(TransferId, 32) || !TransferBytes.HasValue || TransferBytes < 1 || TransferBytes > GeneratedFixture.Maximum || !FixtureProtocol.Alias(Fixture) || Completion != (Command == "CopyFileFromHostToGuest" ? "public_transfer_roundtrip_verified" : "public_transfer_received_verified") || Count.HasValue || Rows != null || Computer != null || Tools.HasValue || Artifact != null || Address != null || Device != null || Variable != null || generated || fixtureProcess : TransferId != null || TransferBytes.HasValue || Completion == "public_transfer_roundtrip_verified" || Completion == "public_transfer_received_verified") throw new BrokerError("worker_protocol_failed");
            if (generated && (Command != "CreateTempfileInGuest" || !FixtureProtocol.Hex(FixtureGeneratedId, 32) || !FixtureGeneratedBytes.HasValue || FixtureGeneratedBytes < 1 || FixtureGeneratedBytes > GeneratedFixture.Maximum)) throw new BrokerError("worker_protocol_failed");
            if (fixtureProbe != Exists.HasValue || (fixtureProbe && (!FixtureProtocol.Alias(Fixture) || Completion != "guest_fixture_observation" || GuestExit.HasValue)) || (!fixtureProbe && !fixtureMutation && !fixtureListing && !fixtureProcess && !transfer && Fixture != null)) throw new BrokerError("worker_protocol_failed");
            if (fixtureProcess)
            {
                try { GuestProcessSupervisor.Slot(FixtureProcessSlot); } catch (BrokerError) { throw new BrokerError("worker_protocol_failed"); }
                if ((Command != "runProgramInGuest" && Command != "killProcessInGuest" && Command != "typeKeystrokesInGuest") || !FixtureProtocol.Alias(Fixture) || FixtureAction != (Command == "runProgramInGuest" ? "start-owned-process" : Command == "typeKeystrokesInGuest" ? "type-owned-fixture" : "stop-owned-process") || Completion != "guest_fixture_process_ack" || GuestExit.HasValue || Count.HasValue || Computer != null || Tools.HasValue) throw new BrokerError("worker_protocol_failed");
            }
            else if (fixtureMutation ? !FixtureProtocol.Alias(Fixture) || FixtureAction != (generated ? "create-generated-file" : GuestFixture.Operation(Command)) || Completion != "guest_fixture_mutation_ack" || GuestExit.HasValue : FixtureAction != null) throw new BrokerError("worker_protocol_failed");
            if (!fixtureMutation && Completion == "guest_fixture_mutation_ack") throw new BrokerError("worker_protocol_failed");
            if (!fixtureProcess && (Completion == "guest_fixture_process_ack" || Command == "killProcessInGuest" || Command == "typeKeystrokesInGuest")) throw new BrokerError("worker_protocol_failed");
            if (fixtureListing && ApprovedEntries != null)
            {
                if (!FixtureProtocol.Alias(Fixture) || Completion != "guest_fixture_approved_listing_observation" || GuestExit.HasValue || FixtureFiles.HasValue || FixtureDirectories.HasValue || Computer != null || Tools.HasValue || Count != ApprovedEntries.Count) throw new BrokerError("worker_protocol_failed");
                try { ApprovedListing.ValidateEntries(ApprovedEntries); } catch (BrokerError) { throw new BrokerError("worker_protocol_failed"); }
            }
            else if (fixtureListing)
            {
                if (!FixtureProtocol.Alias(Fixture) || !FixtureFiles.HasValue || !FixtureDirectories.HasValue || Completion != "guest_fixture_listing_observation" || GuestExit.HasValue) throw new BrokerError("worker_protocol_failed");
                try { new ListingCounts(FixtureFiles.Value, FixtureDirectories.Value); } catch (BrokerError) { throw new BrokerError("worker_protocol_failed"); }
                if (Count != FixtureFiles.Value + FixtureDirectories.Value) throw new BrokerError("worker_protocol_failed");
            }
            else if (FixtureFiles.HasValue || FixtureDirectories.HasValue || Completion == "guest_fixture_listing_observation") throw new BrokerError("worker_protocol_failed");
            if (!fixtureListing && (ApprovedEntries != null || Completion == "guest_fixture_approved_listing_observation")) throw new BrokerError("worker_protocol_failed");
            if (Variable != null)
            {
                if ((Command != "readVariable" && Command != "writeVariable") || !PublicVariable.ValidAlias(Variable) || Computer != null ||
                    (VariableKind != "int32" && VariableKind != "bool") || (VariableKind == "int32" ? !IntegerValue.HasValue || BooleanValue.HasValue : !BooleanValue.HasValue || IntegerValue.HasValue)) throw new BrokerError("worker_protocol_failed");
            }
            else if (VariableKind != null || IntegerValue.HasValue || BooleanValue.HasValue || Command == "writeVariable") throw new BrokerError("worker_protocol_failed");
            if (Command == "readVariable" && Variable == null && Computer == null) throw new BrokerError("worker_protocol_failed");
            if (Address != null && (Command != "getGuestIPAddress" || CliParsing.Address(Address) != Address)) throw new BrokerError("worker_protocol_failed");
            if (Artifact != null && (Command != "captureScreen" || !Target.Hex(Artifact, 32) || !ArtifactBytes.HasValue || ArtifactBytes < 24 || ArtifactBytes > PrivateCapture.MaximumBytes)) throw new BrokerError("worker_protocol_failed");
            if (ArtifactBytes.HasValue && Artifact == null) throw new BrokerError("worker_protocol_failed");
            if (Device != null) { if (Command != "connectNamedDevice" && Command != "disconnectNamedDevice") throw new BrokerError("worker_protocol_failed"); DeviceBinding.Id(Device); }
            if (Backend != "native-vix")
            {
                if (Command == "getGuestIPAddress" && (Address == null || Completion != "bounded_cli_observation")) throw new BrokerError("worker_protocol_failed");
                if ((Command == "listHostNetworks" || Command == "listPortForwardings") && (Inventory == null || Completion != "bounded_cli_observation")) throw new BrokerError("worker_protocol_failed");
                if (Command == "captureScreen" && (Artifact == null || Completion != "private_export_header_checked")) throw new BrokerError("worker_protocol_failed");
                if ((Command == "connectNamedDevice" || Command == "disconnectNamedDevice") && (Device == null || Completion != "cli_completed_not_verified")) throw new BrokerError("worker_protocol_failed");
                if ((Command == "removeSharedFolder" || Command == "disableSharedFolders") && Completion != "cli_completed_not_verified") throw new BrokerError("worker_protocol_failed");
            }
            if (Inventory != null)
            {
                if ((Command != "listHostNetworks" && Command != "listPortForwardings") || Inventory.Count > 256 || Count != Inventory.Count) throw new BrokerError("worker_protocol_failed");
                foreach (InventoryRow item in Inventory)
                {
                    if (item == null) throw new BrokerError("worker_protocol_failed"); CliParsing.NetworkName(item.Name);
                    if (Command == "listHostNetworks") { if (item.Kind != "nat" && item.Kind != "bridged" && item.Kind != "host-only") throw new BrokerError("worker_protocol_failed"); if (item.Address != null || item.HostPort.HasValue || item.GuestPort.HasValue) throw new BrokerError("worker_protocol_failed"); }
                    else { if (item.Kind != "tcp" && item.Kind != "udp") throw new BrokerError("worker_protocol_failed"); if (!item.HostPort.HasValue || !item.GuestPort.HasValue || item.HostPort < 1 || item.HostPort > 65535 || item.GuestPort < 1 || item.GuestPort > 65535 || item.Address == null || CliParsing.Address(item.Address) != item.Address) throw new BrokerError("worker_protocol_failed"); }
                }
            }
            if (Computer != null) Policy.SafeHostname(Computer);
            bool execution = (Command == "runProgramInGuest" || Command == "runScriptInGuest") && !fixtureProcess;
            if (execution != GuestExit.HasValue) throw new BrokerError("worker_protocol_failed");
            if (SnapshotRefs != null)
            {
                if (SnapshotRefs.Count > 256 || Command != "listSnapshots") throw new BrokerError("worker_protocol_failed");
                foreach (string item in SnapshotRefs) if (!System.Text.RegularExpressions.Regex.IsMatch(item, @"^\d{1,3}(/\d{1,3}){0,15}$")) throw new BrokerError("worker_protocol_failed");
            }
            if (Rows != null)
            {
                if (Command != "list" || Rows.Count > 64) throw new BrokerError("worker_protocol_failed");
                int failed = 0; var names = new HashSet<string>();
                foreach (VmStateRow row in Rows)
                {
                    if (row == null || !Target.ValidName(row.Target) || !names.Add(row.Target)) throw new BrokerError("worker_protocol_failed");
                    if (row.Error != null) { if (!ResultData.AllowedError(row.Error) || row.Power.HasValue || row.Tools.HasValue) throw new BrokerError("worker_protocol_failed"); failed++; }
                    else if (!row.Power.HasValue || !row.Tools.HasValue) throw new BrokerError("worker_protocol_failed");
                }
                if (failed != Failures || (failed != 0) != (Completion == "partial_failure")) throw new BrokerError("worker_protocol_failed");
            }
            else if (Failures != 0 || Completion == "partial_failure") throw new BrokerError("worker_protocol_failed");
        }
        internal static OperationReport New(VmrunRequest request)
        {
            return new OperationReport { Command = request.Entry.Name, Backend = request.Entry.Backend, Completion = request.Entry.Risk == "metadata" || request.Entry.Risk == "sensitive-inventory" ? "metadata_only" : "native_completed_not_verified", Authentication = request.NeedsCredential ? "succeeded" : "not_attempted", ScriptCarrier = request.Entry.Name == "runScriptInGuest" ? PinnedScript.Carrier : null, FixtureLaunchMode = request.IsFixtureStart ? NativePlans.FixtureLaunchMode : null };
        }
        internal void SetPublic(PublicVariable policy, PublicScalar scalar)
        {
            policy.Check(scalar); Variable = policy.Alias; VariableKind = scalar.Kind; IntegerValue = scalar.Integer; BooleanValue = scalar.Boolean;
        }
    }
    internal interface ICatalogRuntime
    {
        CapabilityProfile Capabilities(Target target);
        void ValidateTarget(Target target);
        void ConfigureCapabilities(Target target);
    }
    internal static class CatalogEngine
    {
        internal static string Execute(VmrunRequest request, IBrokerRuntime runtime)
        {
            // Explicit unsupported/gated cases stop BEFORE target/files/vault/UI.
            if (!request.EnabledVariant) throw new BrokerError("catalog_operation_unavailable");
            if (HostOperations.Command(request.Entry.Name))
            {
                var host = runtime as IHostOperationsRuntime; if (host == null || request.NeedsCredential || request.Entry.TargetScoped) throw new BrokerError("host_policy_invalid");
                OperationReport report = host.ExecuteHostOperation(request); report.Validate(); return new ResultData { Ok = true, Operation = report }.Json();
            }
            var permissions = runtime as ICatalogRuntime;
            if (permissions == null) throw new BrokerError("capability_policy_invalid");
            if (request.Entry.Backend != "native-vix" && request.Entry.Backend != "native-vix-helper") return CliEngine.Execute(request, runtime, permissions);
            if (request.Entry.Name == "list") return List(request, runtime, permissions).Json();
            Target target = runtime.Resolve(request.TargetName);
            Diagnostics.At(Stage.TargetResolved);
            VmAuthorization authorization = OperationAuthorization.ForVm(runtime, permissions, target, request);
            CapabilityProfile profile = authorization.Profile;
            GuestCredential credential = null;
            bool operationStarted = false;
            try
            {
                OperationReport report;
                using (IBrokerSession session = runtime.Connect())
                {
                    session.OpenTarget(target);
                    session.PrepareOperation(request);
                    authorization.Revalidate();
                    session.PreparePrivateInputs(request, profile);
                    if (request.NeedsCredential)
                    {
                        if (request.Stored) credential = runtime.Acquire(target, true, false);
                        else using (session.UserInteraction()) credential = runtime.Acquire(target, false, false);
                        if (credential.Binding != target.Binding) throw new BrokerError("credential_target_mismatch");
                    }
                    authorization.Revalidate();
                    profile.Demand(target, request); session.Revalidate(target);
                    if (credential != null) session.Login(credential);
                    authorization.Revalidate(); session.Revalidate(target);
                    operationStarted = true; report = session.ExecuteOperation(request, profile);
                }
                report.Validate();
                bool failed = report.GuestExit.HasValue && report.GuestExit != 0;
                return new ResultData { Ok = !failed, ErrorCode = failed ? "guest_program_failed" : null, Target = target.Name, Operation = report }.Json();
            }
            catch (BrokerError error)
            {
                if (operationStarted && (request.IsFixtureStart || GuestFixture.Mutation(request.Entry.Name)) && error.Code != "guest_fixture_helper_refused") throw new BrokerError("guest_fixture_mutation_uncertain");
                throw;
            }
            catch (Exception)
            { if (operationStarted && (request.IsFixtureStart || GuestFixture.Mutation(request.Entry.Name))) throw new BrokerError("guest_fixture_mutation_uncertain"); throw; }
            finally { if (credential != null) { Diagnostics.At(Stage.SecretCleanup); credential.Dispose(); } }
        }
        private static ResultData List(VmrunRequest request, IBrokerRuntime runtime, ICatalogRuntime permissions)
        {
            var report = OperationReport.New(request); report.Rows = new List<VmStateRow>();
            foreach (Target target in runtime.Registered())
            {
                var row = new VmStateRow { Target = target.Name };
                try
                {
                    VmAuthorization authorization = OperationAuthorization.ForVm(runtime, permissions, target, request);
                    using (IBrokerSession session = runtime.Connect())
                    {
                        session.OpenTarget(target);
                        authorization.Revalidate();
                        ResultData status = ResultData.Parse("{\"ok\":true,\"guestAuthentication\":\"not_attempted\"," + session.Status() + "}");
                        row.Power = status.Power; row.Tools = status.Tools;
                    }
                }
                catch (BrokerError error) { row.Power = row.Tools = null; row.Error = ResultData.AllowedError(error.Code) ? error.Code : "local_operation_failed"; report.Failures++; }
                catch (Exception) { row.Power = row.Tools = null; row.Error = "local_operation_failed"; report.Failures++; }
                report.Rows.Add(row);
            }
            report.Count = report.Rows.Count;
            if (report.Failures != 0) report.Completion = "partial_failure";
            return new ResultData { Ok = report.Failures == 0, ErrorCode = report.Failures == 0 ? null : "partial_vm_failure", Operation = report };
        }
    }
}
