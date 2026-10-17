using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.Serialization;
using System.Windows.Forms;

namespace GuestBroker
{
    [DataContract]
    internal sealed class ApprovedProgram
    {
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal string Path { get; set; }
    }
    [DataContract]
    internal sealed class CapabilityProfile
    {
        [DataMember(IsRequired = true)] internal int Version = 1;
        [DataMember(IsRequired = true)] internal string Binding;
        [DataMember(IsRequired = true)] internal string Revision;
        [DataMember(IsRequired = true)] internal bool Disposable;
        [DataMember(IsRequired = true)] internal bool Metadata;
        [DataMember(IsRequired = true)] internal List<string> Commands = new List<string>();
        [DataMember(IsRequired = true)] internal List<ApprovedProgram> Programs = new List<ApprovedProgram>();
        [DataMember(EmitDefaultValue = false)] internal ExportRoot Export { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<ApprovedDevice> Devices { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<ApprovedScript> Scripts { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<string> RemovableShares { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<PublicVariable> PublicVariables { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<GuestFixture> GuestFixtures { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool TimezoneMelbourne { get; set; }
        [DataMember(EmitDefaultValue = false)] internal List<PublicTransferRoot> Transfers { get; set; }
        [DataMember(EmitDefaultValue = false)] internal PublicShare Share { get; set; }
        [DataMember(EmitDefaultValue = false)] internal ExportRoot CloneParent { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string OwnedCloneId { get; set; }
        internal static CapabilityProfile Default(Target target)
        {
            return new CapabilityProfile { Binding = target.Binding, Revision = new string('0', 32), Metadata = true };
        }
        internal void Validate(Target target)
        {
            if (Version != 1 || Binding != target.Binding || !Target.Hex(Revision, 32) || Commands == null || Programs == null || Commands.Count > 47 || Programs.Count > 16) throw new BrokerError("capability_policy_invalid");
            var commands = new HashSet<string>(StringComparer.Ordinal);
            foreach (string command in Commands)
            {
                CatalogEntry entry;
                try { entry = Catalog.Find(command); } catch (BrokerError) { throw new BrokerError("capability_policy_invalid"); }
                if (!commands.Add(command) || !entry.Enabled || !entry.TargetScoped) throw new BrokerError("capability_policy_invalid");
            }
            var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ApprovedProgram program in Programs)
                if (program == null || !Target.ValidName(program.Alias) || !aliases.Add(program.Alias) || !ValidProgramPath(program.Path)) throw new BrokerError("capability_policy_invalid");
            if (Export != null) { HostPaths.ApprovedRoot(Export.Path); if (!Target.Hex(Export.Identity, 64)) throw new BrokerError("capability_policy_invalid"); }
            if (Devices != null)
            {
                if (Devices.Count > 16) throw new BrokerError("capability_policy_invalid"); var ids = new HashSet<string>();
                foreach (ApprovedDevice device in Devices)
                { if (device == null || !ids.Add(device.Id) || !Target.Hex(device.Fingerprint, 64) || !Target.Hex(device.MediaIdentity, 64) || String.IsNullOrEmpty(device.MediaPath)) throw new BrokerError("capability_policy_invalid"); DeviceBinding.Id(device.Id); }
            }
            if (Scripts != null)
            {
                if (Scripts.Count > 8) throw new BrokerError("script_policy_invalid"); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (ApprovedScript script in Scripts) { if (script == null || !names.Add(script.Alias)) throw new BrokerError("script_policy_invalid"); script.Validate(); }
            }
            if (RemovableShares != null)
            {
                if (RemovableShares.Count > 16) throw new BrokerError("share_not_approved"); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string share in RemovableShares) { VmrunRequest.Label(share); if (!names.Add(share)) throw new BrokerError("share_not_approved"); }
            }
            if (PublicVariables != null)
            {
                if (PublicVariables.Count > 16) throw new BrokerError("public_variable_policy_invalid"); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (PublicVariable variable in PublicVariables) { if (variable == null || !names.Add(variable.Alias)) throw new BrokerError("public_variable_policy_invalid"); variable.Validate(); }
            }
            if (GuestFixtures != null)
            {
                if (GuestFixtures.Count > 8) throw new BrokerError("guest_fixture_policy_invalid"); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (GuestFixture fixture in GuestFixtures) { if (fixture == null || !names.Add(fixture.Alias)) throw new BrokerError("guest_fixture_policy_invalid"); fixture.Validate(); }
            }
            if (Transfers != null)
            {
                if (Transfers.Count > 4) throw new BrokerError("transfer_policy_invalid"); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (PublicTransferRoot item in Transfers) { if (item == null || !names.Add(item.Alias)) throw new BrokerError("transfer_policy_invalid"); item.Validate(); }
            }
            if (Share != null) Share.Validate();
            if (CloneParent != null) { OwnedClones.Parent(target, CloneParent); if (!Target.Hex(CloneParent.Identity, 64)) throw new BrokerError("owned_clone_refused"); }
            if (OwnedCloneId != null && !Target.Hex(OwnedCloneId, 32)) throw new BrokerError("owned_clone_refused");
        }
        internal static bool ValidProgramPath(string path)
        {
            // Exact Windows guest executable opt-in, not a host file lookup or a
            // promise of remote canonicalization. Execution is explicitly privileged.
            if (String.IsNullOrEmpty(path) || path.Length > 240 || path.Length < 8 || path[1] != ':' || path[2] != '\\' || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
            if (path.IndexOfAny(new[] { '/', '"', '*', '?', '\0', '\r', '\n' }) >= 0 || path.IndexOf(':', 2) >= 0) return false;
            foreach (char c in path) if (Char.IsControl(c)) return false;
            try { new System.Text.UTF8Encoding(false, true).GetByteCount(path); } catch (ArgumentException) { return false; }
            foreach (string part in path.Substring(3).Split('\\')) if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)) return false;
            return true;
        }
        internal void Demand(Target target, VmrunRequest request)
        {
            Validate(target);
            if (!request.EnabledVariant) throw new BrokerError("catalog_operation_unavailable");
            if (target.Name == "SAFE-DC" && (GuestFixture.Mutation(request.Entry.Name) || request.IsFixtureStart || PublicTransfers.Command(request.Entry.Name) || PublicSharing.Command(request.Entry.Name) || request.Entry.Name == "clone" || request.Entry.Name == "deleteVM" || request.Entry.Name == "upgradevm")) throw new BrokerError("protected_target_refused");
            if (request.Entry.NeedsDisposable && !Disposable) throw new BrokerError("disposable_target_required");
            if (!(request.Entry.Risk == "metadata" && Metadata) && !Commands.Contains(request.Entry.Name)) throw new BrokerError("capability_not_granted");
            if (request.Entry.Name == "runProgramInGuest" && !request.IsFixtureStart) Program(request.Arguments[0]);
            if (request.Entry.Name == "runScriptInGuest") Script(request.Arguments[0]);
            if (PublicTransfers.Command(request.Entry.Name)) Transfer(request.Arguments[0]);
            if (request.Entry.Name == "clone" && CloneParent == null || request.Entry.Name == "deleteVM" && OwnedCloneId == null) throw new BrokerError("owned_clone_refused");
            if (PublicSharing.Command(request.Entry.Name))
            {
                if (Share == null || (request.Entry.Name != "enableSharedFolders" && request.Arguments[0] != Share.Name)) throw new BrokerError("public_share_not_approved");
                if (request.Entry.Name == "enableSharedFolders" && request.Arguments.Length != 0) throw new BrokerError("unsupported_operation_option");
            }
            if (request.Entry.Name == "removeSharedFolder" && (RemovableShares == null || !RemovableShares.Contains(request.Arguments[0]))) throw new BrokerError("share_not_approved");
            if (request.Entry.Name == "captureScreen" && Export == null) throw new BrokerError("export_root_not_approved");
            if (request.Entry.Name == "connectNamedDevice" || request.Entry.Name == "disconnectNamedDevice") Device(request.Arguments[0]);
            if (request.IsPublicVariable)
            {
                PublicVariable variable = Variable(request.Arguments[1]);
                if (request.Entry.Name == "readVariable" && !variable.Read) throw new BrokerError("public_variable_not_granted");
                if (request.Entry.Name == "writeVariable") { if (!variable.Write) throw new BrokerError("public_variable_not_granted"); variable.Check(PublicScalar.Parse(request.Arguments[2])); }
            }
            if (GuestFixture.RequestIsHelper(request))
            {
                GuestFixture fixture = Fixture(GuestFixture.RootAlias(request));
                fixture.DemandImage(request);
                if ((request.IsFixtureStart || GuestFixture.ProcessStop(request.Entry.Name) || GuestFixture.ProcessType(request.Entry.Name)) && !fixture.OwnedProcesses) throw new BrokerError("guest_fixture_process_refused");
                if (GuestFixture.ProcessType(request.Entry.Name) && !fixture.OwnedSink) throw new BrokerError("guest_fixture_process_refused");
                if (request.IsGeneratedFixture && !fixture.GeneratedFixtures) throw new BrokerError("guest_fixture_owned_refused");
                if (!request.IsFixtureStart && !request.IsGeneratedFixture && GuestOwned.Operation(GuestFixture.Operation(request.Entry.Name)) && !fixture.OwnedMutations) throw new BrokerError("guest_fixture_owned_refused");
                if (request.IsApprovedListing) fixture.NamedPlan(request.Arguments[1]);
                else if (GuestFixture.Listing(request.Entry.Name) && !fixture.PublicListing) throw new BrokerError("guest_fixture_listing_refused");
                if (GuestFixture.Rename(request.Entry.Name) && !fixture.OwnedRenames) throw new BrokerError("guest_fixture_owned_refused");
                if (GuestFixture.Delete(request.Entry.Name) && !fixture.OwnedDeletes) throw new BrokerError("guest_fixture_owned_refused");
            }
        }
        internal void DemandTimezone(Target target)
        {
            Validate(target);
            if (target.Name == "SAFE-DC") throw new BrokerError("protected_target_refused");
            if (!Disposable) throw new BrokerError("disposable_target_required");
            if (!TimezoneMelbourne) throw new BrokerError("capability_not_granted");
        }
        internal ApprovedDevice Device(string id)
        {
            if (Devices != null) foreach (ApprovedDevice device in Devices) if (device.Id == id) return device;
            throw new BrokerError("device_not_approved");
        }
        internal ApprovedProgram Program(string alias)
        {
            foreach (ApprovedProgram program in Programs) if (program.Alias == alias) return program;
            throw new BrokerError("program_not_approved");
        }
        internal ApprovedScript Script(string alias)
        {
            if (Scripts != null) foreach (ApprovedScript script in Scripts) if (script.Alias == alias) return script;
            throw new BrokerError("script_not_approved");
        }
        internal PublicVariable Variable(string alias)
        {
            if (PublicVariables != null) foreach (PublicVariable variable in PublicVariables) if (variable.Alias == alias) return variable;
            throw new BrokerError("public_variable_not_granted");
        }
        internal GuestFixture Fixture(string alias)
        {
            if (GuestFixtures != null) foreach (GuestFixture fixture in GuestFixtures) if (fixture.Alias == alias) return fixture;
            throw new BrokerError("guest_fixture_not_approved");
        }
        internal PublicTransferRoot Transfer(string alias)
        {
            if (Transfers != null) foreach (PublicTransferRoot item in Transfers) if (item.Alias == alias) return item;
            throw new BrokerError("transfer_not_approved");
        }
        internal string Fingerprint()
        {
            using (var stream = new System.IO.MemoryStream())
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(CapabilityProfile)).WriteObject(stream, this);
                return BitConverter.ToString(sha.ComputeHash(stream.ToArray()));
            }
        }
    }
    internal static class CapabilityDialog
    {
        internal static CapabilityProfile Edit(Target target, CapabilityProfile current)
        {
            using (var form = new Form { Text = "Broker policy - " + target.Name, ClientSize = new Size(760, 640), StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false })
            using (var disposable = new CheckBox { Text = "Disposable UNPROMOTED test VM, NOT a domain controller", Left = 16, Top = 78, Width = 720, Checked = current.Disposable })
            using (var metadata = new CheckBox { Text = "Allow bounded native metadata queries", Left = 16, Top = 108, Width = 720, Checked = current.Metadata })
            using (var commands = new CheckedListBox { Left = 16, Top = 140, Width = 720, Height = 240 })
            using (var programs = new TextBox { Left = 16, Top = 420, Width = 720, Height = 130, Multiline = true, ScrollBars = ScrollBars.Vertical })
            using (var export = new TextBox { Left = 12, Top = 54, Width = 560, ReadOnly = true, Text = current.Export == null ? "" : current.Export.Path })
            using (var devices = new TextBox { Left = 12, Top = 150, Width = 670, Height = 190, Multiline = true, ScrollBars = ScrollBars.Vertical })
            using (var removableShares = new TextBox { Left = 12, Top = 48, Width = 680, Height = 280, Multiline = true, ScrollBars = ScrollBars.Vertical })
            using (var publicVariables = new TextBox { Left = 12, Top = 96, Width = 680, Height = 245, Multiline = true, ScrollBars = ScrollBars.Vertical })
            using (var guestFixtures = new TextBox { Left = 12, Top = 196, Width = 680, Height = 150, Multiline = true, ScrollBars = ScrollBars.Vertical })
            using (var approvedNames = new TextBox { Left = 12, Top = 100, Width = 680, Height = 245, Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 16384 })
            using (var timezone = new CheckBox { Dock = DockStyle.Bottom, Height = 45, Checked = current.TimezoneMelbourne, Text = "Allow fixed timezone-melbourne on this disposable VM (unattended once configured)" })
            using (var transfers = new TextBox { Left = 12, Top = 114, Width = 680, Height = 230, Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 4096 })
            {
                ExportRoot chosenExport = current.Export;
                PublicShare chosenShare = current.Share;
                var chosenScripts = current.Scripts == null ? new List<ApprovedScript>() : new List<ApprovedScript>(current.Scripts);
                form.Controls.Add(new Label { Text = target.Name + "\n" + target.Vmx + "\nUUID " + target.Uuid, Left = 16, Top = 12, Width = 720, Height = 62 });
                foreach (CatalogEntry entry in Catalog.Entries) if (entry.Enabled && entry.TargetScoped) commands.Items.Add(entry.Name, current.Commands.Contains(entry.Name));
                var lines = new List<string>(); foreach (ApprovedProgram program in current.Programs) lines.Add(program.Alias + "=" + program.Path);
                programs.Lines = lines.ToArray();
                var tabs = new TabControl { Left = 16, Top = 140, Width = 720, Height = 410 };
                var commandTab = new TabPage("Command grants"); commands.Dock = DockStyle.Fill; commandTab.Controls.Add(commands);
                commandTab.Controls.Add(timezone);
                var programTab = new TabPage("Privileged programs");
                programTab.Controls.Add(new Label { Text = "One alias=C:\\absolute\\program.exe per line. Shell aliases grant general\nguest code execution. NON-SECRET arguments only; no raw output.", Left = 12, Top = 12, Width = 680, Height = 42 });
                programs.SetBounds(12, 60, 680, 300); programTab.Controls.Add(programs);
                var exportTab = new TabPage("Private export / optical devices");
                exportTab.Controls.Add(new Label { Text = "Private PNG export: choose an existing non-secret local scratch directory.\nOnly new pinned private capture files are created; no arbitrary output path.", Left = 12, Top = 10, Width = 680, Height = 40 });
                var browse = new Button { Text = "Choose root", Left = 580, Top = 52, Width = 100 };
                browse.Click += delegate
                {
                    using (var picker = new FolderBrowserDialog())
                    { picker.Description = "Approve an existing local non-secret scratch export root"; picker.ShowNewFolderButton = false; if (picker.ShowDialog(form) == DialogResult.OK) { chosenExport = ExportRoot.Capture(picker.SelectedPath); export.Text = chosenExport.Path; } }
                };
                exportTab.Controls.AddRange(new Control[] { export, browse });
                exportTab.Controls.Add(new Label { Text = "Exact ISO-backed optical device IDs, one per line (example sata0:1).\nNO NIC/USB/disk/physical-drive grants. Save binds type, ISO path and file identity.\nConnecting media can trigger guest autorun. Existing VNC/key fields are NOT read.", Left = 12, Top = 88, Width = 680, Height = 58 });
                var ids = new List<string>(); if (current.Devices != null) foreach (ApprovedDevice device in current.Devices) ids.Add(device.Id); devices.Lines = ids.ToArray(); exportTab.Controls.Add(devices);
                var scriptTab = new TabPage("Private hashed scripts");
                scriptTab.Controls.Add(new Label { Text = "NON-SECRET UTF-8 .ps1 code only (max 16 KiB), no passwords/tokens/keys.\nEnrollment privately pins root, file identity and SHA-256. Execution is privileged,\nNOT a file sandbox; interpreter startup/profile code may also run.", Left = 12, Top = 12, Width = 680, Height = 55 });
                var aliasBox = new TextBox { Left = 12, Top = 80, Width = 150 };
                var interpreterBox = new TextBox { Left = 12, Top = 130, Width = 660 };
                scriptTab.Controls.Add(new Label { Text = "Alias (exact spelling):", Left = 12, Top = 60, Width = 200 });
                scriptTab.Controls.Add(new Label { Text = "Exact guest WindowsPowerShell interpreter path (no default):", Left = 12, Top = 110, Width = 660 });
                var scriptsBox = new ListBox { Left = 12, Top = 200, Width = 660, Height = 125 };
                Action refreshScripts = delegate { scriptsBox.Items.Clear(); foreach (ApprovedScript script in chosenScripts) scriptsBox.Items.Add(script.Alias + "  SHA256 " + script.Sha256); };
                refreshScripts();
                var enroll = new Button { Text = "Choose / pin .ps1", Left = 12, Top = 164, Width = 150 };
                enroll.Click += delegate
                {
                    try
                    {
                        using (var picker = new OpenFileDialog())
                        {
                            picker.Title = "Choose explicitly approved NON-SECRET code, never credential/key files"; picker.Filter = "Non-secret PowerShell code (*.ps1)|*.ps1"; picker.Multiselect = false;
                            if (picker.ShowDialog(form) == DialogResult.OK)
                            {
                                ApprovedScript script = ApprovedScript.Enroll(aliasBox.Text, picker.FileName, interpreterBox.Text);
                                if (chosenScripts.Count >= 8) throw new BrokerError("script_policy_invalid");
                                if (Native.MessageBoxW(IntPtr.Zero, "Enroll this exact NON-SECRET code for " + target.Name + "?\nAlias: " + script.Alias + "\nSHA256: " + script.Sha256 + "\nInterpreter: " + script.Interpreter + "\nBy approving, I confirm I reviewed the code and it contains NO passwords, tokens, private keys or credential material. Execution is privileged, not a sandbox. This is enrollment only, not execution approval.", "Review exact code enrollment", 0x4 | 0x100 | 0x30 | 0x40000) == 6)
                                { chosenScripts.Add(script); refreshScripts(); }
                            }
                        }
                    }
                    catch (BrokerError error) { Native.MessageBoxW(IntPtr.Zero, ResultData.AllowedError(error.Code) ? error.Code : "script_policy_invalid", "Code selection refused", 0x10); }
                    catch (Exception) { Native.MessageBoxW(IntPtr.Zero, "Code selection failed; no code enrolled. Raw diagnostics suppressed.", "Code selection refused", 0x10); }
                };
                var removeScript = new Button { Text = "Remove selected", Left = 180, Top = 164, Width = 150 };
                removeScript.Click += delegate { if (scriptsBox.SelectedIndex >= 0) { chosenScripts.RemoveAt(scriptsBox.SelectedIndex); refreshScripts(); } };
                scriptTab.Controls.AddRange(new Control[] { aliasBox, interpreterBox, scriptsBox, enroll, removeScript });
                var shareTab = new TabPage("Access-reducing sharing");
                shareTab.Controls.Add(new Label { Text = "Exact NON-SECRET share names eligible for removeSharedFolder, one per line.\nThis removes guest access only; no host path lookup or deletion. New sharing\nexposure is NOT granted. Configured operations run unattended, no operation prompt.", Left = 12, Top = 6, Width = 680, Height = 42 });
                removableShares.Lines = current.RemovableShares == null ? new string[0] : current.RemovableShares.ToArray(); shareTab.Controls.Add(removableShares);
                var variableTab = new TabPage("Typed public variables");
                variableTab.Controls.Add(new Label { Text = "PUBLIC NON-SECRET runtime values only; no passwords/tokens/private data.\nOne alias|int32|MIN|MAX|r/w/rw or alias|bool|r/w/rw per line.\nExample: progress|int32|0|100|rw  (use rw, NOT literal r/w/rw).\nBroker computes its own guestVar key; no environment/config/custom key input.\nRead/write need command+alias policy; writes need disposable VM. Operation UI is deferred.", Left = 12, Top = 8, Width = 680, Height = 82 });
                var variableLines = new List<string>(); if (current.PublicVariables != null) foreach (PublicVariable variable in current.PublicVariables) variableLines.Add(variable.PolicyLine()); publicVariables.Lines = variableLines.ToArray(); variableTab.Controls.Add(publicVariables);
                var fixtureTab = new TabPage("Manually bootstrapped guest roots");
                fixtureTab.Controls.Add(new TextBox { ReadOnly = true, Multiline = true, Left = 12, Top = 8, Width = 680, Height = 105, Text = UiText.Lines("MANUAL guest-side bootstrap / independent review required; no auto copy/install.\nHost target binding (PUBLIC): " + target.Binding + "\nRequired compiled helper image SHA256: " + HelperBuild.Hash + "\nOn the trusted disposable guest, verify image hash and use enroll-root UI.\nSame-user/admin/malicious guest code is NOT isolated by this protocol.") });
                fixtureTab.Controls.Add(new Label { Text = "Receipt: rootAlias|PUBLIC-ID|C:\\approved\\broker-guest-helper.exe[|FLAGS]\nFLAGS: owned-empty,public-counts,owned-rename,owned-delete,owned-process,generated-fixture,owned-sink\nMatching scoped guest+host rights required; no operation prompt. Unchanged legacy3 receipt keeps its image.\nowned-delete DESTROYS whole owned test objects + streams; trees refuse ANY foreign child.", Left = 12, Top = 116, Width = 680, Height = 80 });
                var fixtureLines = new List<string>(); if (current.GuestFixtures != null) foreach (GuestFixture fixture in current.GuestFixtures) fixtureLines.Add(fixture.PolicyLine()); guestFixtures.Lines = fixtureLines.ToArray(); fixtureTab.Controls.Add(guestFixtures);
                var namedTab = new TabPage("Approved PUBLIC names");
                namedTab.Controls.Add(new Label { Left = 12, Top = 8, Width = 680, Height = 88, Text = "Explicit named-metadata grant, NOT inherited from counts/creation/rename.\nrootAlias|relativeDirectory|entryAlias|basename|KIND (KIND is literal file OR directory)\nAt most8 entries / ONE directory per root. Match guest manifest EXACTLY, including case.\nOnly enrolled host names/kinds may be returned; digest mismatch or unknown observed entries refuse.\nBlank rows revoke this optional grant. NON-SECRET fixture metadata ONLY." });
                var namedLines = new List<string>();
                if (current.GuestFixtures != null) foreach (GuestFixture fixture in current.GuestFixtures) if (fixture.ApprovedListing != null)
                    foreach (string line in fixture.ApprovedListing.Lines()) namedLines.Add(fixture.Alias + "|" + line);
                approvedNames.Lines = namedLines.ToArray(); namedTab.Controls.Add(approvedNames);
                var transferTab = new TabPage("PUBLIC native transfer");
                transferTab.Controls.Add(new Label { Left = 12, Top = 8, Width = 680, Height = 100, Text = "GENERATED PUBLIC fixtures ONLY, <=1MiB. One alias|HOST-ROOT|GUEST-ROOT per line.\nHost: existing local scratch path <=70 chars. Guest: existing dedicated Windows PUBLIC root.\nExample: public|D:\\BrokerScratch|C:\\brokertest-transfer\nNo helper/bootstrap needed. VIX path semantics trust same-user/guest; NOT an atomic sandbox.\nOnly fresh computed filenames / own prior generated sources; no arbitrary file import.\nPrivate artifacts retained after failures/timeouts; do not reuse or auto-delete unknown paths." });
                var transferLines = new List<string>(); if (current.Transfers != null) foreach (PublicTransferRoot item in current.Transfers) transferLines.Add(item.Alias + "|" + item.Host.Path + "|" + item.Guest);
                transfers.Lines = transferLines.ToArray(); transferTab.Controls.Add(transfers);
                var publicShareTab = new TabPage("NEW PUBLIC shared folder");
                publicShareTab.Controls.Add(new Label { Left = 12, Top = 8, Width = 680, Height = 100, Text = "Only a NEW dedicated PUBLIC fixture folder; never an existing user tree.\nCreates one generated 1024-byte public.bin under a fresh broker-share-ID directory.\nadd requires NO existing shares. enable/set require ONLY the exact owned mapping.\nThis is not a filesystem sandbox against the guest/same host user. Guest writes may alter fixtures.\nRuntime-only enable option is not implemented; native completion is not guest mount proof." });
                var publicShareName = new TextBox { Left = 12, Top = 120, Width = 240, Text = chosenShare == null ? "publicfixture" : chosenShare.Name };
                var publicShareInfo = new Label { Left = 12, Top = 220, Width = 680, Height = 100, Text = chosenShare == null ? "No public share grant." : chosenShare.Name + "\n" + chosenShare.Root.Path };
                var newShare = new Button { Left = 12, Top = 160, Width = 270, Text = "Create NEW public fixture folder" };
                newShare.Click += delegate
                {
                    try
                    {
                        using (var picker = new FolderBrowserDialog())
                        {
                            picker.Description = "Choose existing NONSECRET local scratch parent (<=60 chars); a NEW public child is created"; picker.ShowNewFolderButton = false;
                            if (picker.ShowDialog(form) == DialogResult.OK)
                            { chosenShare = PublicShare.Create(picker.SelectedPath, publicShareName.Text); publicShareInfo.Text = chosenShare.Name + "\n" + chosenShare.Root.Path + "\nCreated during setup; remains if policy save is cancelled."; }
                        }
                    }
                    catch (Exception) { Native.MessageBoxW(IntPtr.Zero, "Public fixture setup failed. No existing tree is adopted. Any new residue is left for review.", "Public share setup", 0x10); }
                };
                var revokeShare = new Button { Left = 310, Top = 160, Width = 200, Text = "Clear grant (no deletion)" };
                revokeShare.Click += delegate { chosenShare = null; publicShareInfo.Text = "No public share grant; no existing mapping or directory was removed."; };
                publicShareTab.Controls.AddRange(new Control[] { publicShareName, publicShareInfo, newShare, revokeShare });
                tabs.TabPages.AddRange(new[] { commandTab, programTab, scriptTab, shareTab, variableTab, fixtureTab, namedTab, exportTab, transferTab, publicShareTab }); form.Controls.Add(tabs);
                var accept = new Button { Text = "Review/save", Left = 490, Top = 580, Width = 115, DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancel", Left = 620, Top = 580, Width = 115, DialogResult = DialogResult.Cancel };
                form.Controls.AddRange(new Control[] { disposable, metadata, accept, cancel }); form.CancelButton = cancel;
                if (form.ShowDialog() != DialogResult.OK) throw new BrokerError("user_cancelled");
                var result = new CapabilityProfile { Binding = target.Binding, Revision = Guid.NewGuid().ToString("N").ToUpperInvariant(), Disposable = disposable.Checked, Metadata = metadata.Checked, TimezoneMelbourne = timezone.Checked };
                foreach (string command in commands.CheckedItems) result.Commands.Add(command);
                foreach (string line in programs.Lines)
                {
                    if (String.IsNullOrWhiteSpace(line)) continue;
                    int equals = line.IndexOf('='); if (equals < 1) throw new BrokerError("capability_policy_invalid");
                    result.Programs.Add(new ApprovedProgram { Alias = line.Substring(0, equals), Path = line.Substring(equals + 1) });
                }
                result.Export = chosenExport;
                result.Share = chosenShare;
                result.CloneParent = current.CloneParent; result.OwnedCloneId = current.OwnedCloneId; // CLI nonsecret setup owns these scoped receipts.
                if (chosenScripts.Count != 0) result.Scripts = chosenScripts;
                if (removableShares.Lines.Length != 0)
                { result.RemovableShares = new List<string>(); foreach (string line in removableShares.Lines) if (!String.IsNullOrWhiteSpace(line)) result.RemovableShares.Add(line); }
                if (publicVariables.Lines.Length != 0)
                { result.PublicVariables = new List<PublicVariable>(); foreach (string line in publicVariables.Lines) if (!String.IsNullOrWhiteSpace(line)) result.PublicVariables.Add(PublicVariable.PolicyLine(line)); }
                if (guestFixtures.Lines.Length != 0)
                {
                    result.GuestFixtures = new List<GuestFixture>();
                    foreach (string line in guestFixtures.Lines) if (!String.IsNullOrWhiteSpace(line))
                    {
                        GuestFixture fixture = GuestFixture.SetupLine(line, current.GuestFixtures);
                        result.GuestFixtures.Add(fixture);
                    }
                }
                GuestFixture.AttachNamedPlans(result.GuestFixtures, approvedNames.Lines);
                foreach (string line in transfers.Lines) if (!String.IsNullOrWhiteSpace(line))
                {
                    string[] parts = line.Split('|'); if (parts.Length != 3) throw new BrokerError("transfer_policy_invalid");
                    var item = new PublicTransferRoot { Alias = parts[0], Host = ExportRoot.Capture(parts[1]), Guest = parts[2] }; item.Validate();
                    if (result.Transfers == null) result.Transfers = new List<PublicTransferRoot>(); result.Transfers.Add(item);
                }
                if (devices.Lines.Length != 0)
                {
                    result.Devices = new List<ApprovedDevice>();
                    foreach (string line in devices.Lines) if (!String.IsNullOrWhiteSpace(line)) result.Devices.Add(DeviceBinding.Capture(target, line));
                }
                result.Validate(target);
                string namedReview = "";
                if (result.GuestFixtures != null) foreach (GuestFixture fixture in result.GuestFixtures) if (fixture.ApprovedListing != null)
                    namedReview += "\nPUBLIC name grant for " + fixture.Alias + " / digest " + fixture.ApprovedListing.Digest() + "\n" + String.Join("\n", fixture.ApprovedListing.Lines()) + "\n";
                if (Native.MessageBoxW(IntPtr.Zero, "Save this exact registration's policy?\n" + target.Name + "\n" + target.Vmx + namedReview + "\nConfigured operations run UNATTENDED; per-operation approval is DEFERRED. Scope/identity/ownership checks remain. Never mark a real DC or protected VM disposable.", "Review broker capability SETUP", 0x4 | 0x100 | 0x30 | 0x40000) != 6) throw new BrokerError("user_cancelled");
                return result;
            }
        }
    }
}
