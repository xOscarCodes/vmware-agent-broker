using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace GuestBroker
{
    internal static class Tests
    {
        private static int count;
        private static string currentTest = "test initialization";
        private static void Assert(bool condition) { if (!condition) throw new Exception("assertion failed"); }
        private static void Test(string name, Action action)
        {
            currentTest = name;
            Diagnostics.Current = Stage.Starting; Diagnostics.Failure = null; Diagnostics.Channel = null; GuestUsernameNormalization.Form = null;
            action(); count++; Console.WriteLine("PASS " + name);
        }
        private static void Reject(Action action, string code)
        {
            try { action(); }
            catch (BrokerError e) { Assert(e.Code == code); return; }
            throw new Exception("expected rejection");
        }
        private static Request RequestFor(params string[] args) { return Request.Parse(args); }
        private static Target Synthetic(string name, char digit)
        {
            return new Target { Name = name, Vmx = @"D:\SyntheticBrokerFixtures\" + name + ".vmx", Uuid = new string(digit, 32), FileIdentity = new string(digit, 64), Generation = new string(digit, 32) };
        }
        private static void WithRegistry(Action<string, RegistryStore> action)
        {
            string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "registry-test-" + Guid.NewGuid().ToString("N"));
            try { action(root, new RegistryStore(root, delegate (string temp, string destination, bool exists) { if (exists) File.Replace(temp, destination, null); else File.Move(temp, destination); })); }
            finally
            {
                // Only this test's newly created GUID directory, no recursive delete.
                if (Directory.Exists(root)) { foreach (string file in Directory.GetFiles(root)) File.Delete(file); Directory.Delete(root); }
            }
        }

        private sealed class FakeRuntime : IBrokerRuntime, ICatalogRuntime, IOfficialCliRuntime, IRegistrationMetadataRuntime, IHostOperationsRuntime
        {
            internal readonly List<string> Events = new List<string>();
            internal bool FailConnect, FailLogin, FailDispose, Consent = true;
            internal bool WrongIdentity, CrossCredential;
            internal string Hostname = "SYNTHETIC-GUEST";
            internal GuestCredential Credential;
            internal int LiveSessions;
            internal bool RevokePolicyAtPrepare;
            internal bool MutatePolicyAtPrepare;
            internal bool RevokePolicyAtSecondRead;
            internal bool RebindMetadataAtPrepare;
            internal bool HostAllowed;
            internal Func<string, string, Target> MetadataRefresh;
            private int policyReads;
            internal string BadTargetName;
            internal int GuestProgramExit;
            internal bool ScriptChanged;
            internal bool FailInteractiveLogin;
            internal int? LastLoginOptions, LastProgramOptions;
            internal readonly RegistryDocument Document = new RegistryDocument { Targets = new List<Target> { Synthetic("SAFE-DC", '1'), Synthetic("TEST-VM", '2') } };
            internal readonly List<string> Selected = new List<string>();
            internal readonly Dictionary<string, CapabilityProfile> Policies = new Dictionary<string, CapabilityProfile>();
            public Target Resolve(string name) { return Document.Resolve(name); }
            public Target[] Registered() { return Document.Targets.ToArray(); }
            public Target RefreshKnownVm(string name, string binding) { Events.Add("metadata-refresh"); if (MetadataRefresh == null) throw new BrokerError("registration_refresh_unavailable"); return MetadataRefresh(name, binding); }
            public void Register() { Events.Add("register-private-ui"); }
            public void Unregister(Target target) { Events.Add("unregister"); Selected.Add(target.Name); }
            public IBrokerSession Connect()
            {
                Events.Add("connect");
                if (FailConnect) throw new BrokerError("missing_vix_export");
                LiveSessions++;
                return new FakeSession(this);
            }
            public GuestCredential Acquire(Target target, bool stored, bool persist)
            {
                Assert(LiveSessions == 1); // Native session stays live across prompt.
                Events.Add(stored ? "vault" : "prompt");
                var user = new SecretBuffer(20);
                var password = new SecretBuffer(20);
                Marshal.WriteInt16(user.Pointer, (short)'u');
                Marshal.WriteInt16(password.Pointer, (short)'p');
                Credential = new GuestCredential(CrossCredential ? Resolve("TEST-VM") : target, user, password);
                return Credential;
            }
            public void Save(Target target, GuestCredential credential) { Events.Add("save"); Selected.Add(target.Name); Assert(LiveSessions == 0 && credential.Password.Pointer != IntPtr.Zero && credential.Binding == target.Binding); }
            public bool ApproveTimezone(Target target) { Events.Add("consent"); throw new Exception("unexpected operation approval callback"); }
            public void Revoke(Target target) { Events.Add("revoke"); Selected.Add(target.CredentialKey); }
            public CapabilityProfile Capabilities(Target target)
            {
                Events.Add("policy"); policyReads++;
                if (RevokePolicyAtSecondRead && policyReads == 2) Policies[target.Binding] = CapabilityProfile.Default(target);
                CapabilityProfile value; return Policies.TryGetValue(target.Binding, out value) ? value : CapabilityProfile.Default(target);
            }
            public void ValidateTarget(Target target) { Events.Add("validate-target"); if (WrongIdentity) throw new BrokerError("vm_identity_changed_reenroll_required"); }
            public bool ApproveOperation(Target target, VmrunRequest request, CapabilityProfile profile)
            {
                Events.Add("operation-consent"); throw new Exception("unexpected operation approval callback");
            }
            public void ConfigureCapabilities(Target target) { Events.Add("configure-policy-private-ui"); }
            public bool ApproveHostRead(VmrunRequest request) { Events.Add("host-read-consent"); throw new Exception("unexpected operation approval callback"); }
            public OperationReport ExecuteOfficialCli(VmrunRequest request, Target target, CapabilityProfile profile)
            {
                Events.Add("official-cli:" + request.Entry.Name);
                if (target != null) Selected.Add(target.Name);
                var result = OperationReport.New(request); result.Completion = "bounded_cli_observation";
                switch (request.Entry.Name)
                {
                    case "getGuestIPAddress": result.Address = "192.0.2.42"; break;
                    case "listHostNetworks": result.Inventory = new List<InventoryRow> { new InventoryRow { Name = "vmnet1", Kind = "host-only" } }; result.Count = 1; break;
                    case "listPortForwardings": result.Inventory = new List<InventoryRow>(); result.Count = 0; break;
                    case "captureScreen": result.Artifact = new string('A', 32); result.ArtifactBytes = 128; result.Completion = "private_export_header_checked"; break;
                    case "connectNamedDevice": case "disconnectNamedDevice": result.Device = request.Arguments[0]; result.Completion = "cli_completed_not_verified"; break;
                    default: result.Completion = "cli_completed_not_verified"; break;
                }
                return result;
            }
            public OperationReport ExecuteHostOperation(VmrunRequest request)
            {
                Events.Add("machine-policy");
                if (!HostAllowed) throw new BrokerError(request.Entry.Name == "downloadPhotonVM" ? "photon_policy_required" : "forward_policy_required");
                Events.Add("host-operation:" + request.Entry.Name); var report = OperationReport.New(request);
                if (request.Entry.Name == "downloadPhotonVM") { report.PhotonId = new string('A', 32); report.DownloadBytes = PhotonDownload.Minimum; report.Completion = "official_photon_image_verified"; }
                else { report.MappingId = new string('A', 32); report.Completion = request.Entry.Name == "setPortForwarding" ? "owned_forward_added" : "owned_forward_restored"; }
                return report;
            }
        }

        private sealed class FakeSession : IBrokerSession
        {
            private readonly FakeRuntime runtime;
            private bool authenticated;
            private bool operationPrepared;
            private int preparedLoginOptions;
            internal FakeSession(FakeRuntime r) { runtime = r; }
            public int ApiVersion { get { return -1; } }
            public void OpenTarget(Target target)
            {
                runtime.Events.Add("open"); runtime.Selected.Add(target.Name);
                if (runtime.WrongIdentity || target.Name == runtime.BadTargetName) throw new BrokerError("vm_identity_changed_reenroll_required");
            }
            public void Revalidate(Target target) { runtime.Events.Add("revalidate"); runtime.Selected.Add(target.Name); }
            public IDisposable UserInteraction() { return new FakeInteraction(); }
            private sealed class FakeInteraction : IDisposable { public void Dispose() { } }
            public string Status() { runtime.Events.Add("status"); return "\"powerState\":8,\"toolsState\":2"; }
            public void Login(GuestCredential credential)
            {
                runtime.Events.Add("login");
                runtime.LastLoginOptions = preparedLoginOptions;
                Assert(credential.Password.Pointer != IntPtr.Zero);
                if (runtime.FailInteractiveLogin && preparedLoginOptions == NativePlans.RequireInteractiveEnvironment) throw new BrokerError("vix_error_3034");
                if (runtime.FailLogin) throw new BrokerError("vix_error_3024");
                authenticated = true;
            }
            public string Identity() { Assert(authenticated); runtime.Events.Add("identity"); return runtime.Hostname; }
            public void SetMelbourneTimezone() { Assert(authenticated); runtime.Events.Add("timezone"); }
            public OperationReport ExecuteOperation(VmrunRequest request, CapabilityProfile profile)
            {
                Assert(authenticated == request.NeedsCredential);
                Assert(operationPrepared && preparedLoginOptions == NativePlans.LoginOptions(request));
                if (request.Entry.Name == "runProgramInGuest" || GuestFixture.RequestIsHelper(request)) runtime.LastProgramOptions = NativePlans.Flags(request);
                runtime.Events.Add("operation:" + request.Entry.Name);
                var result = OperationReport.New(request);
                switch (request.Entry.Name)
                {
                    case "checkToolsState": result.Tools = 2; break;
                    case "listSnapshots": result.Count = 2; if (request.Arguments.Length != 0) result.SnapshotRefs = new List<string> { "0", "0/0" }; break;
                    case "listProcessesInGuest": result.Count = 3; break;
                    case "readVariable":
                        if (request.IsPublicVariable) { PublicVariable variable = profile.Variable(request.Arguments[1]); result.SetPublic(variable, PublicScalar.Parse(variable.Kind == "bool" ? "true" : "3")); }
                        else result.Computer = "SYNTHETIC-GUEST"; break;
                    case "writeVariable": result.SetPublic(profile.Variable(request.Arguments[1]), PublicScalar.Parse(request.Arguments[2])); break;
                    case "fileExistsInGuest": case "directoryExistsInGuest": result.Fixture = request.Arguments[0]; result.Exists = true; result.Completion = "guest_fixture_observation"; break;
                    case "listDirectoryInGuest":
                        if (request.IsApprovedListing) GuestFixture.CompleteApproved(result, request.Arguments[0], profile.Fixture(request.Arguments[0]).NamedPlan(request.Arguments[1]), ApprovedListing.ExitBase + 1);
                        else GuestFixture.Complete(result, request.Arguments[0], new ListingCounts(2, 1).Encode()); break;
                    case "CreateTempfileInGuest":
                        if (request.IsGeneratedFixture) GuestFixture.CompleteGenerated(result, request, request.Arguments[0], 0);
                        else { result.Fixture = request.Arguments[0]; result.FixtureAction = GuestFixture.Operation(request.Entry.Name); result.Completion = "guest_fixture_mutation_ack"; }
                        break;
                    case "createDirectoryInGuest": case "renameFileInGuest": case "deleteFileInGuest": case "deleteDirectoryInGuest": result.Fixture = request.Arguments[0]; result.FixtureAction = GuestFixture.Operation(request.Entry.Name); result.Completion = "guest_fixture_mutation_ack"; break;
                    case "killProcessInGuest": case "typeKeystrokesInGuest": GuestFixture.CompleteProcess(result, request, request.Arguments[0], 0); break;
                    case "runProgramInGuest":
                        if (request.IsFixtureStart) GuestFixture.CompleteProcess(result, request, request.Arguments[1], 0);
                        else result.GuestExit = runtime.GuestProgramExit; break;
                    case "runScriptInGuest": result.GuestExit = runtime.GuestProgramExit; break;
                    case "CopyFileFromHostToGuest":
                    case "CopyFileFromGuestToHost":
                        result.TransferId = new string('A', 32); result.TransferBytes = 32; result.Fixture = "public";
                        result.Completion = request.Entry.Name == "CopyFileFromHostToGuest" ? "public_transfer_roundtrip_verified" : "public_transfer_received_verified"; break;
                    case "addSharedFolder":
                    case "setSharedFolderState":
                    case "enableSharedFolders":
                        result.ShareName = "synthetic"; result.Completion = request.Entry.Name == "enableSharedFolders" ? "native_completed_not_verified" : "public_share_mapping_verified"; break;
                    case "clone": case "deleteVM": result.CloneId = new string('A', 32); result.Completion = request.Entry.Name == "clone" ? "owned_full_clone_created" : "owned_clone_deleted"; break;
                }
                return result;
            }
            public void PrepareOperation(VmrunRequest request)
            {
                runtime.Events.Add("prepare-operation"); Target target = runtime.Resolve(request.TargetName);
                Assert(!operationPrepared && !authenticated); preparedLoginOptions = NativePlans.LoginOptions(request); operationPrepared = true;
                if (runtime.RevokePolicyAtPrepare) runtime.Policies[target.Binding] = CapabilityProfile.Default(target);
                if (runtime.MutatePolicyAtPrepare) runtime.Policies[target.Binding].Commands.Clear();
                if (runtime.RebindMetadataAtPrepare) { Target item = runtime.Document.Targets.Find(delegate (Target value) { return value.Name == target.Name; }); item.IdentityMode = "path-uuid-v1"; item.ObservedFileIdentity = item.FileIdentity; item.IdentityRevision = 1; }
            }
            public void PreparePrivateInputs(VmrunRequest request, CapabilityProfile profile)
            {
                runtime.Events.Add("prepare-private-inputs");
                if (request.Entry.Name == "runScriptInGuest" && runtime.ScriptChanged) throw new BrokerError("script_identity_changed");
            }
            public void Dispose()
            {
                runtime.LiveSessions--;
                runtime.Events.Add("dispose");
                if (authenticated) Assert(runtime.Credential.Password.Pointer != IntPtr.Zero);
                if (runtime.FailDispose && authenticated) throw new BrokerError("vix_error_1");
            }
        }

        internal static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "fixture-idle") { System.Threading.Thread.Sleep(35000); return 0; }
            if (args.Length == 3 && args[0] == "fixture-sink") return PublicFixtureSink.RunForTest(args[1], args[2]);
            if (args.Length == 11 && args[0] == "--supervise-fixture-test" && args[9] == "--owner-job")
            {
                var store = new GuestRootStore(args[1]); GuestRootRecord root = store.Read(args[3], args[4]);
                if (root.EnrollmentId != args[5] || root.ImageSha256 != args[6]) return FixtureProtocol.NotEnrolled;
                try { return GuestProcessSupervisor.Run(store, root, args[7], args[8], Int32.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture), args[10]); }
                catch (Exception error) { return unchecked((int)(0xE1000000u | (uint)(error.HResult & 0xffff))); }
            }
            if (args.Length >= 2 && args[0] == "--synthetic-cli") return SyntheticCli(args);
            if (args.Length >= 4 && args[0] == "--broker-worker") return SyntheticWorker(args);
            if (args.Length == 1 && args[0] == "--watchdog-child")
            {
                using (var deadline = new Deadline(100)) { System.Threading.Thread.Sleep(20000); }
                return 99;
            }
            try
            {
                Test("held typed enrollment snapshot permits atomic revocation while preserving old snapshot and observing new next read", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        Assert(record.OwnedProcesses && store.Read(record.TargetBinding, record.Alias).OwnedProcesses);
                        bool published = false;
                        store.ReadSnapshotOpened = delegate (string kind, FileStream held)
                        {
                            Assert(kind == "enrollment" && held.CanRead); store.ReadSnapshotOpened = null;
                            bool inPlaceBlocked = false, directoryPinned = false;
                            try { using (var writer = new FileStream(held.Name, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)) { } } catch (IOException) { inPlaceBlocked = true; }
                            string directory = Path.GetDirectoryName(held.Name);
                            try { Directory.Move(directory, directory + "-move"); } catch (IOException) { directoryPinned = true; }
                            if (!directoryPinned) Directory.Move(directory + "-move", directory);
                            Assert(inPlaceBlocked && directoryPinned);
                            record.OwnedProcesses = false; store.Save(record); published = true;
                        };
                        GuestRootRecord old = store.Read(record.TargetBinding, record.Alias);
                        Assert(published && old.OwnedProcesses && !store.Read(record.TargetBinding, record.Alias).OwnedProcesses && !GuestProcessSupervisor.Current(store, record));
                    });
                });
                Test("held typed owned-ledger snapshot permits atomic tombstone publication without losing old snapshot or fixture data pins", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "owned.txt"); OwnedLedger replacement = store.ReadOwned(record); replacement.Items[0].Deleted = true;
                        bool published = false;
                        using (var fixture = new FileStream(Path.Combine(root, "owned.txt"), FileMode.Open, FileAccess.Read, FileShare.Read))
                        using (FixtureParent parent = FixtureParent.Open(record, "owned.txt"))
                        {
                            store.ReadSnapshotOpened = delegate (string kind, FileStream held)
                            {
                                Assert(kind == "owned" && held.CanRead); store.ReadSnapshotOpened = null;
                                using (store.MutationLock()) store.WriteOwned(record, replacement); published = true;
                                bool dataBlocked = false;
                                try { File.Delete(Path.Combine(root, "owned.txt")); } catch (IOException) { dataBlocked = true; }
                                Assert(dataBlocked && File.Exists(Path.Combine(root, "owned.txt")) && fixture.Length == 0);
                            };
                            OwnedLedger old = store.ReadOwned(record);
                            Assert(published && !old.Items[0].Deleted && store.ReadOwned(record).Items[0].Deleted && old.EnrollmentId == record.EnrollmentId);
                        }
                    });
                });
                Test("held typed process-marker snapshot permits exact removal while immutable instance snapshot remains valid", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        var marker = new FixtureProcessRecord { Binding = record.TargetBinding, RootAlias = record.Alias, Enrollment = record.EnrollmentId, Image = record.ImageSha256, Slot = "slot4", Instance = Guid.NewGuid().ToString("N").ToUpperInvariant(), Supervisor = 1, Created = 1, Expires = DateTime.UtcNow.AddSeconds(30).Ticks };
                        using (store.MutationLock()) store.WriteProcess(record, marker);
                        bool removed = false;
                        store.ReadSnapshotOpened = delegate (string kind, FileStream held)
                        {
                            Assert(kind == "process" && held.CanRead); store.ReadSnapshotOpened = null;
                            using (store.MutationLock()) store.RemoveProcess(record, marker); removed = true;
                        };
                        FixtureProcessRecord old = store.ReadProcess(record, marker.Slot);
                        Assert(removed && old.Instance == marker.Instance && old.Created == marker.Created && !store.ProcessExists(record, marker.Slot));
                    });
                });
                Test("atomic revocation with held enrollment reader and real owned supervisor exits within original lease bound without arbitrary process kill", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000); FixtureProcessRecord process = store.ReadProcess(record, "slot1");
                        IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, process.Supervisor);
                        try
                        {
                            Assert(view != IntPtr.Zero);
                            store.ReadSnapshotOpened = delegate (string kind, FileStream held)
                            {
                                Assert(kind == "enrollment" && held.CanRead); store.ReadSnapshotOpened = null;
                                record.OwnedProcesses = false; store.Save(record);
                            };
                            GuestRootRecord old = store.Read(record.TargetBinding, record.Alias);
                            Assert(old.OwnedProcesses && !store.Read(record.TargetBinding, record.Alias).OwnedProcesses);
                            Assert(Native.WaitForSingleObject(view, 5000) == 0 && !store.ProcessExists(record, "slot1"));
                            Reject(delegate { GuestProcessSupervisor.Stop(store, record, "slot1"); }, "guest_fixture_process_refused");
                        }
                        finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                    });
                });
                Test("strict request grammar, named targets, no caller path or all selector", delegate
                {
                    Assert(RequestFor("probe").Operation == "probe");
                    Assert(RequestFor("identity", "SAFE-DC", "--stored").Stored);
                    Assert(RequestFor("enroll", "SAFE-DC", "--persist").Persist);
                    string[][] invalid = {
                        new[] { "probe", "SAFE-DC" }, new[] { "status", "all" , "--all" },
                        new[] { "status", @"D:\SyntheticBrokerFixtures\SAFE-DC.vmx" }, new[] { "exec", "SAFE-DC" }, new[] { "status", "bad name" },
                        new[] { "identity", "SAFE-DC", "--password=synthetic" }, new[] { "revoke", "SAFE-DC", "--stored" },
                        new[] { "timezone-melbourne", "SAFE-DC", "--persist" }, new[] { "enroll", "SAFE-DC", "--stored" },
                        new[] { "identity", "SAFE-DC", "--stored", "extra" }, new[] { "status", "SAFE-DC", "--stored" }
                    };
                    foreach (string[] invalidArgs in invalid) Reject(delegate { Request.Parse(invalidArgs); }, "invalid_request");
                });
                Test("credential key binds VMX UUID file identity name and generation", delegate
                {
                    Target a = Synthetic("SAFE-DC", '1'), b = Synthetic("TEST-VM", '2');
                    Assert(a.CredentialKey != b.CredentialKey);
                    Target change = a.Clone(); change.Generation = new string('3', 32); Assert(a.CredentialKey != change.CredentialKey);
                    change = a.Clone(); change.Name = "safe-dc"; Assert(a.CredentialKey != change.CredentialKey);
                    change = a.Clone(); change.Uuid = new string('3', 32); Assert(a.CredentialKey != change.CredentialKey);
                    change = a.Clone(); change.FileIdentity = new string('3', 64); Assert(a.CredentialKey != change.CredentialKey);
                    change = a.Clone(); change.Vmx = @"D:\SyntheticBrokerFixtures\Renamed.vmx"; Assert(a.CredentialKey != change.CredentialKey);
                    Assert(Policy.TimezoneProgram == @"C:\Windows\System32\tzutil.exe");
                    Assert(Policy.TimezoneArguments == "/s \"AUS Eastern Standard Time\"");
                });
                Test("two registered VMs list without native access, status selects exactly one", delegate
                {
                    var f = new FakeRuntime();
                    string result = Broker.Execute(RequestFor("list"), f);
                    Assert(result.Contains("SAFE-DC") && result.Contains("TEST-VM") && f.Events.Count == 0);
                    foreach (string name in new[] { "SAFE-DC", "TEST-VM" })
                    {
                        f = new FakeRuntime();
                        result = Broker.Execute(RequestFor("status", name), f);
                        Assert(result.Contains("\"target\":\"" + name + "\"") && result.Contains("not_attempted"));
                        Assert(String.Join(",", f.Selected) == name && !f.Events.Contains("login"));
                    }
                });
                Test("unknown and wrong-case names never select first VM or access native API", delegate
                {
                    foreach (string name in new[] { "UNKNOWN", "safe-dc", "all" })
                    {
                        var f = new FakeRuntime();
                        Reject(delegate { Broker.Execute(RequestFor("identity", name, "--stored"), f); }, "unknown_target");
                        Assert(f.Events.Count == 0 && f.Selected.Count == 0);
                    }
                });
                Test("identity and fixed timezone operate on second registered VM only", delegate
                {
                    foreach (string op in new[] { "identity", "timezone-melbourne" })
                    {
                        var f = new FakeRuntime();
                        if (op == "timezone-melbourne") GrantTimezone(f);
                        string result = Broker.Execute(RequestFor(op, "TEST-VM", "--stored"), f);
                        Assert(result.Contains("\"target\":\"TEST-VM\""));
                        foreach (string selected in f.Selected) Assert(selected == "TEST-VM");
                        Assert(f.Credential.Binding == f.Resolve("TEST-VM").Binding && f.Credential.Password.Pointer == IntPtr.Zero);
                    }
                });
                Test("wrong VM identity fails before credential access", delegate
                {
                    var f = new FakeRuntime { WrongIdentity = true };
                    Reject(delegate { Broker.Execute(RequestFor("identity", "SAFE-DC", "--stored"), f); }, "vm_identity_changed_reenroll_required");
                    Assert(String.Join(",", f.Events) == "connect,open,dispose");
                });
                Test("native VM handle pathname must match selected target, never another VM", delegate
                {
                    string a = Synthetic("SAFE-DC", '1').Vmx, b = Synthetic("TEST-VM", '2').Vmx;
                    Policy.RequireSameTargetPath(a.ToLowerInvariant(), a);
                    Reject(delegate { Policy.RequireSameTargetPath(b, a); }, "native_target_mismatch");
                    Reject(delegate { Policy.RequireSameTargetPath(null, a); }, "native_target_mismatch");
                });
                Test("cross-target transient credential is rejected before guest login", delegate
                {
                    var f = new FakeRuntime { CrossCredential = true };
                    Reject(delegate { Broker.Execute(RequestFor("identity", "SAFE-DC", "--stored"), f); }, "credential_target_mismatch");
                    Assert(!f.Events.Contains("login") && f.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("Credential Manager metadata rejects credential crossover without vault access", delegate
                {
                    Target a = Synthetic("SAFE-DC", '1'), b = Synthetic("TEST-VM", '2');
                    var cred = new Native.Credential(); cred.Type = 1;
                    cred.Target = Marshal.StringToHGlobalUni(a.CredentialKey);
                    cred.Comment = Marshal.StringToHGlobalUni(a.Binding);
                    try
                    {
                        GuestCredential.ValidateBinding(a, cred);
                        Reject(delegate { GuestCredential.ValidateBinding(b, cred); }, "credential_target_mismatch");
                    }
                    finally { Marshal.FreeHGlobal(cred.Target); Marshal.FreeHGlobal(cred.Comment); }
                });
                Test("per-VM revoke deletes only selected binding without native VM access", delegate
                {
                    var f = new FakeRuntime();
                    Broker.Execute(RequestFor("revoke", "TEST-VM"), f);
                    Assert(String.Join(",", f.Events) == "revoke");
                    Assert(f.Selected.Count == 1 && f.Selected[0] == f.Resolve("TEST-VM").CredentialKey && f.Selected[0] != f.Resolve("SAFE-DC").CredentialKey);
                });
                Test("duplicate aliases, case, UUID, file identity and generations rejected", delegate
                {
                    Target a = Synthetic("SAFE-DC", '1');
                    for (int i = 0; i < 5; i++)
                    {
                        Target b = Synthetic("TEST-VM", '2');
                        if (i == 0) b.Name = "safe-dc";
                        if (i == 1) b.Vmx = a.Vmx.ToLowerInvariant();
                        if (i == 2) b.Uuid = a.Uuid;
                        if (i == 3) b.FileIdentity = a.FileIdentity;
                        if (i == 4) b.Generation = a.Generation;
                        var document = new RegistryDocument { Targets = new List<Target> { a, b } };
                        Reject(document.Validate, "duplicate_registration");
                    }
                    foreach (string path in new[] { @"D:\x\..\y.vmx", @"D:\x\file.vmx:stream", @"\\server\VM\x.vmx", @"D:\x.\a.vmx" }) Assert(!Target.ValidPath(path));
                });
                Test("private ACL registry roundtrip, two targets and exact per-target removal", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Assert(store.Read().Targets.Count == 0 && !Directory.Exists(root));
                        Target a = Synthetic("SAFE-DC", '1'), b = Synthetic("TEST-VM", '2');
                        store.Add(a); store.Add(b);
                        Assert(store.Read().Targets.Count == 2 && store.Read().Resolve("TEST-VM").Binding == b.Binding);
                        Target duplicate = a.Clone(); duplicate.Name = "safe-dc";
                        Reject(delegate { store.Add(duplicate); }, "duplicate_registration");
                        Assert(store.Read().Targets.Count == 2);
                        store.Remove(a);
                        Assert(store.Read().Targets.Count == 1 && store.Read().Resolve("TEST-VM").Binding == b.Binding);
                        Reject(delegate { store.Read().Resolve("SAFE-DC"); }, "unknown_target");
                    });
                });
                Test("exclusive writer lock fails immediately without lost registry update", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        store.Add(Synthetic("SAFE-DC", '1'));
                        using (var held = new FileStream(Path.Combine(root, "registry.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                            Reject(delegate { store.Add(Synthetic("TEST-VM", '2')); }, "registry_writer_unavailable");
                        Assert(store.Read().Targets.Count == 1);
                    });
                });
                Test("atomic publish failure retains old complete registry and removes temp", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target a = Synthetic("SAFE-DC", '1'); store.Add(a);
                        var failing = new RegistryStore(root, delegate { throw new IOException("synthetic publication failure"); });
                        bool failed = false;
                        try { failing.Add(Synthetic("TEST-VM", '2')); } catch (IOException) { failed = true; }
                        Assert(failed && store.Read().Targets.Count == 1 && store.Read().Resolve("SAFE-DC").Binding == a.Binding);
                        Assert(Directory.GetFiles(root, "registry.new.*").Length == 0);
                    });
                });
                Test("version-2 registration and credential key stay compatible with prior delivery", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target legacy = Synthetic("Legacy-VM", '1'); store.Add(legacy);
                        string json = "{\"Version\":2,\"Targets\":[{\"Name\":\"Legacy-VM\",\"Vmx\":\"D:\\\\SyntheticBrokerFixtures\\\\Legacy-VM.vmx\",\"Uuid\":\"" + new string('1', 32) + "\",\"FileIdentity\":\"" + new string('1', 64) + "\",\"Generation\":\"" + new string('1', 32) + "\"}]}";
                        File.WriteAllText(Path.Combine(root, "registry.json"), json);
                        Target loaded = store.Read().Resolve("Legacy-VM");
                        Assert(loaded.CredentialKey == "VmwareGuestBroker/v2/E8A47BA89F3C0A3624889E2B30B26BE2305BF294FD05BEEBB848453DBDD44743");
                        Assert(loaded.Binding == legacy.Binding);
                    });
                });
                Test("corrupt registry fails closed, never silently resets allowlist", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        store.Add(Synthetic("SAFE-DC", '1'));
                        foreach (string invalid in new[] { "not JSON", "{}", "{\"Version\":3,\"Targets\":[]}", "{\"Version\":2,\"Targets\":[{}]}", "{\"Version\":2,\"Version\":2,\"Targets\":[]}", "{\"Version\":2,\"Targets\":[]} trailing" })
                        {
                            File.WriteAllText(Path.Combine(root, "registry.json"), invalid);
                            Reject(delegate { store.Read(); }, "corrupt_registry");
                        }
                    });
                });
                Test("registry with broader-than-current-user ACL is rejected", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        store.Add(Synthetic("SAFE-DC", '1'));
                        string path = Path.Combine(root, "registry.json");
                        var security = File.GetAccessControl(path);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"), System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow));
                        File.SetAccessControl(path, security);
                        Reject(delegate { store.Read(); }, "registry_acl_rejected");
                    });
                });
                Test("only allowlisted VMX UUID field is interpreted; missing and duplicate rejected", delegate
                {
                    string line = "uuid.bios = \"11 11 11 11 11 11 11 11-11 11 11 11 11 11 11 11\"\n";
                    using (var input = new MemoryStream(Encoding.UTF8.GetBytes("ignored.key = \"SYNTHETIC-IGNORED\"\n" + line))) Assert(VmIdentity.ReadUuid(input) == new string('1', 32));
                    foreach (string invalid in new[] { "other = 1\n", line + line, line + line.Replace("uuid.bios", "UUID.BIOS"), "uuid.bios = \"bad\"\n" })
                        using (var input = new MemoryStream(Encoding.UTF8.GetBytes(invalid))) Reject(delegate { VmIdentity.ReadUuid(input); }, "vm_identity_unavailable");
                });
                Test("legacy strict VMX records reject physical replacement until explicit logical identity rebind", delegate
                {
                    string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "identity-" + Guid.NewGuid().ToString("N") + ".vmx");
                    string temp = file + ".new";
                    string original = "uuid.bios = \"" + new string('1', 32) + "\"\n";
                    try
                    {
                        File.WriteAllText(file, original);
                        Target target = VmIdentity.Capture("Synthetic", file);
                        target.IdentityMode = null; target.ObservedFileIdentity = null; target.IdentityRevision = 0; // Exact old v2 semantics.
                        using (var pin = VmIdentity.Open(target)) Assert(pin.Length > 0);
                        File.WriteAllText(file, "uuid.bios = \"" + new string('2', 32) + "\"\n");
                        Reject(delegate { using (VmIdentity.Open(target)) { } }, "vm_identity_changed_reenroll_required");
                        File.WriteAllText(file, original);
                        File.WriteAllText(temp, original); File.Replace(temp, file, null);
                        Reject(delegate { using (VmIdentity.Open(target)) { } }, "vm_identity_changed_reenroll_required");
                        Target renewed = VmIdentity.Capture("Synthetic", file);
                        Assert(renewed.CredentialKey != target.CredentialKey);
                    }
                    finally { if (File.Exists(temp)) File.Delete(temp); if (File.Exists(file)) File.Delete(file); }
                });
                Test("bounded hostname rejects output injection", delegate
                {
                    Assert(Policy.SafeHostname("WIN-123") == "WIN-123");
                    foreach (string value in new[] { "", "bad\nvalue", "a\"b", "\\host", "not.ascii", "\u00e9", new string('A', 64) })
                        Reject(delegate { Policy.SafeHostname(value); }, "invalid_guest_identity");
                });
                Test("PE parser fails closed on truncated and hostile offsets", delegate
                {
                    foreach (byte[] value in new[] { new byte[0], new byte[64], new byte[128] })
                        Reject(delegate { Policy.VerifyImage(value); }, "invalid_pe");
                    var image = new byte[128]; image[0] = (byte)'M'; image[1] = (byte)'Z';
                    Buffer.BlockCopy(BitConverter.GetBytes(Int32.MaxValue), 0, image, 60, 4);
                    Reject(delegate { Policy.VerifyImage(image); }, "invalid_pe");
                    Buffer.BlockCopy(BitConverter.GetBytes(64), 0, image, 60, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(0x4550), 0, image, 64, 4);
                    Reject(delegate { Policy.VerifyImage(image); }, "unsupported_architecture");
                    Buffer.BlockCopy(BitConverter.GetBytes((short)0x14c), 0, image, 68, 2);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)0x10b), 0, image, 88, 2);
                    Policy.VerifyImage(image);
                });
                Test("hash pin rejects synthetic image", delegate
                {
                    using (var stream = new MemoryStream(new byte[64]))
                        Reject(delegate { Policy.VerifyHash(stream); }, "unreviewed_vix_binary");
                });
                Test("canonical file handle is pinned against replacement during use", delegate
                {
                    string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "synthetic-pin-" + Guid.NewGuid().ToString("N") + ".txt");
                    try
                    {
                        File.WriteAllText(file, "synthetic non-secret metadata");
                        using (FileStream pin = Policy.OpenPinned(file))
                        {
                            bool blocked = false;
                            try { using (new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } }
                            catch (IOException) { blocked = true; }
                            Assert(blocked && pin.Length > 0);
                        }
                    }
                    finally { if (File.Exists(file)) File.Delete(file); }
                });
                Test("volatile wipe clears exact region, not adjacent canaries", delegate
                {
                    IntPtr p = Marshal.AllocHGlobal(34);
                    try
                    {
                        for (int i = 0; i < 34; i++) Marshal.WriteByte(p, i, 0xa5);
                        SecretBuffer.Wipe(IntPtr.Add(p, 1), 32);
                        Assert(Marshal.ReadByte(p) == 0xa5 && Marshal.ReadByte(p, 33) == 0xa5);
                        for (int i = 1; i <= 32; i++) Assert(Marshal.ReadByte(p, i) == 0);
                    }
                    finally { SecretBuffer.Wipe(p, 34); Marshal.FreeHGlobal(p); }
                });
                Test("buffer bounds and idempotent cleanup", delegate
                {
                    Reject(delegate { new SecretBuffer(0); }, "credential_size_rejected");
                    Reject(delegate { new SecretBuffer(65537); }, "credential_size_rejected");
                    using (var b = new SecretBuffer(4))
                    {
                        Marshal.WriteInt16(b.Pointer, 0, 1); Marshal.WriteInt16(b.Pointer, 2, 1);
                        Reject(delegate { b.WideLength(); }, "credential_size_rejected");
                        Reject(delegate { b.CopyFrom(b.Pointer, 5, 0); }, "credential_size_rejected");
                        b.Dispose(); b.Dispose(); Assert(b.Pointer == IntPtr.Zero);
                    }
                });
                Test("native UTF8 conversion preserves synthetic Unicode and terminator", delegate
                {
                    using (var b = new SecretBuffer(10))
                    {
                        Marshal.WriteInt16(b.Pointer, 0, (short)'X');
                        Marshal.WriteInt16(b.Pointer, 2, 0x00e9);
                        using (var encoded = b.Utf8())
                        {
                            Assert(encoded.Size == 4);
                            Assert(Marshal.ReadByte(encoded.Pointer, 0) == 0x58);
                            Assert(Marshal.ReadByte(encoded.Pointer, 1) == 0xc3);
                            Assert(Marshal.ReadByte(encoded.Pointer, 2) == 0xa9);
                            Assert(Marshal.ReadByte(encoded.Pointer, 3) == 0);
                        }
                    }
                });
                Test("empty and malformed UTF16 credentials rejected", delegate
                {
                    using (var b = new SecretBuffer(8))
                    {
                        Reject(delegate { b.Utf8(); }, "empty_credential_rejected");
                        Marshal.WriteInt16(b.Pointer, 0, unchecked((short)0xd800));
                        Reject(delegate { b.Utf8(); }, "credential_encoding_rejected");
                    }
                });
                Test("x86 Win32 structure ABI sizes", delegate
                {
                    Assert(IntPtr.Size == 4);
                    Assert(Marshal.SizeOf(typeof(Native.CredUi)) == 20);
                    Assert(Marshal.SizeOf(typeof(Native.Credential)) == 52);
                    Assert(Marshal.SizeOf(typeof(Native.TrustFile)) == 16);
                    Assert(Marshal.SizeOf(typeof(Native.TrustData)) == 52);
                    Assert(Marshal.SizeOf(typeof(Native.FileInformation)) == 52);
                    Assert(Marshal.SizeOf(typeof(Native.FileIdInformation)) == 24);
                    Assert(Marshal.SizeOf(typeof(Native.SecurityAttributes)) == 12);
                    Assert(Marshal.SizeOf(typeof(Native.StartupInfo)) == 68);
                    Assert(Marshal.SizeOf(typeof(Native.StartupInfoEx)) == 72);
                    Assert(Marshal.SizeOf(typeof(Native.ProcessInformation)) == 16);
                });
                Test("watchdog terminates only synthetic child with native exit 124", delegate
                {
                    var start = new System.Diagnostics.ProcessStartInfo(typeof(Tests).Assembly.Location, "--watchdog-child");
                    start.UseShellExecute = false;
                    start.CreateNoWindow = true;
                    using (var child = System.Diagnostics.Process.Start(start))
                    {
                        if (!child.WaitForExit(5000)) { child.Kill(); child.WaitForExit(); throw new Exception("watchdog failed"); }
                        Assert(child.ExitCode == 124);
                    }
                });
                Test("probe and status never acquire credentials", delegate
                {
                    foreach (Request r in new[] { RequestFor("probe"), RequestFor("status", "SAFE-DC") })
                    {
                        var f = new FakeRuntime();
                        Assert(Broker.Execute(r, f).Contains("\"ok\":true"));
                        Assert(!f.Events.Contains("prompt") && !f.Events.Contains("vault") && !f.Events.Contains("login"));
                    }
                });
                Test("unsupported native API fails before prompt vault or consent", delegate
                {
                    foreach (Request r in new[] { RequestFor("enroll", "SAFE-DC", "--persist"), RequestFor("identity", "SAFE-DC", "--stored"), RequestFor("timezone-melbourne", "TEST-VM") })
                    {
                        var f = new FakeRuntime { FailConnect = true };
                        if (r.Operation == "timezone-melbourne") GrantTimezone(f);
                        Reject(delegate { Broker.Execute(r, f); }, "missing_vix_export");
                        Assert(f.Events.Contains("connect") && f.Credential == null && !f.Events.Contains("consent"));
                    }
                });
                Test("timezone missing policy stops before native or credential access without an approval callback", delegate
                {
                    var f = new FakeRuntime { Consent = false };
                    Reject(delegate { Broker.Execute(RequestFor("timezone-melbourne", "TEST-VM", "--stored"), f); }, "disposable_target_required");
                    Assert(!f.Events.Contains("connect") && f.Credential == null && !f.Events.Contains("consent"));
                });
                Test("failed login prevents save and guest mutation, clears buffers", delegate
                {
                    foreach (Request r in new[] { RequestFor("enroll", "SAFE-DC", "--persist"), RequestFor("timezone-melbourne", "TEST-VM") })
                    {
                        var f = new FakeRuntime { FailLogin = true };
                        if (r.Operation == "timezone-melbourne") GrantTimezone(f);
                        Reject(delegate { Broker.Execute(r, f); }, "vix_error_3024");
                        Assert(!f.Events.Contains("save") && !f.Events.Contains("timezone"));
                        Assert(f.Credential.Password.Pointer == IntPtr.Zero && f.Credential.User.Pointer == IntPtr.Zero);
                    }
                });
                Test("enrollment storage is explicit and only after successful native login", delegate
                {
                    var f = new FakeRuntime();
                    Broker.Execute(RequestFor("enroll", "SAFE-DC", "--persist"), f);
                    Assert(String.Join(",", f.Events) == "connect,open,prompt,revalidate,login,dispose,save");
                    f = new FakeRuntime();
                    Broker.Execute(RequestFor("enroll", "SAFE-DC"), f);
                    Assert(!f.Events.Contains("save"));
                });
                Test("stored identity has narrow result and tears native session down before wiping", delegate
                {
                    var f = new FakeRuntime();
                    string result = Broker.Execute(RequestFor("identity", "SAFE-DC", "--stored"), f);
                    Assert(result.Contains("SYNTHETIC-GUEST") && !result.Contains("Password"));
                    Assert(String.Join(",", f.Events) == "connect,open,vault,revalidate,login,identity,dispose");
                    Assert(f.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("guest output injection fails closed and still disposes", delegate
                {
                    var f = new FakeRuntime { Hostname = "evil\"\n" };
                    Reject(delegate { Broker.Execute(RequestFor("identity", "SAFE-DC"), f); }, "invalid_guest_identity");
                    Assert(f.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("cleanup error suppresses success and still clears managed-owned secrets", delegate
                {
                    var f = new FakeRuntime { FailDispose = true };
                    Reject(delegate { Broker.Execute(RequestFor("identity", "SAFE-DC"), f); }, "vix_error_1");
                    Assert(f.Credential.Password.Pointer == IntPtr.Zero);
                    f = new FakeRuntime { FailDispose = true };
                    Reject(delegate { Broker.Execute(RequestFor("enroll", "SAFE-DC", "--persist"), f); }, "vix_error_1");
                    Assert(!f.Events.Contains("save") && f.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("configured fixed timezone authenticates unattended, never arbitrary inputs or SAFE-DC", delegate
                {
                    var f = new FakeRuntime { Consent = false }; GrantTimezone(f);
                    string result = Broker.Execute(RequestFor("timezone-melbourne", "TEST-VM", "--stored"), f);
                    Assert(!f.Events.Contains("consent") && f.Events.Contains("vault") && f.Events.Contains("timezone") && f.Events.IndexOf("revalidate") < f.Events.IndexOf("login"));
                    Assert(result.Contains("not_verified"));
                });
                Test("revocation is target-only and independent of VMware availability", delegate
                {
                    var f = new FakeRuntime { FailConnect = true };
                    Broker.Execute(RequestFor("revoke", "SAFE-DC"), f);
                    Assert(String.Join(",", f.Events) == "revoke");
                });
                Test("invalid synthetic secret argument is never echoed", delegate
                {
                    var old = Console.Out;
                    var output = new StringWriter();
                    try
                    {
                        Console.SetOut(output);
                        Assert(Program.Main(new[] { "identity", "SAFE-DC", "--password=SYNTHETIC-NOT-A-REAL-SECRET" }) == 2);
                    }
                    finally { Console.SetOut(old); }
                    Assert(output.ToString().Contains("invalid_request") && !output.ToString().Contains("SYNTHETIC") && !output.ToString().StartsWith("{", StringComparison.Ordinal));
                });
                Test("help version and optional output grammar have no native side effects", delegate
                {
                    Assert(RequestFor().Operation == "help" && RequestFor("--help").Operation == "help" && RequestFor("--version").Operation == "version");
                    Request r = RequestFor("status", "SAFE-DC", "--json", "--diagnostic");
                    Assert(r.Json && r.Diagnostic && r.TargetName == "SAFE-DC");
                    Reject(delegate { RequestFor("list", "--json", "--json"); }, "invalid_request");
                    Reject(delegate { RequestFor("--json", "list"); }, "invalid_request");
                    Reject(delegate { RequestFor("help", "--json"); }, "invalid_request");
                    Assert(Output.Help.Contains(".\\bin\\guest-broker.exe list") && Output.Help.Contains(".\\guest-broker.exe status") && Output.Version.Contains("x86"));
                });
                Test("human list distinguishes empty and two registered VMs with aligned safe columns", delegate
                {
                    string empty = Output.Human(ResultData.Parse("{\"ok\":true,\"registeredVMs\":[],\"guestAuthentication\":\"not_attempted\"}"));
                    Assert(empty.Contains("No VMs registered") && !empty.StartsWith("{", StringComparison.Ordinal));
                    string two = Output.Human(ResultData.Parse(Broker.Execute(RequestFor("list"), new FakeRuntime())));
                    Assert(two.Contains("NAME     STATE") && two.Contains("SAFE-DC  Registered") && two.Contains("TEST-VM  Registered"));
                    Assert(two.Contains("not attempted") && !two.Contains("\u001b"));
                });
                Test("human status and native probe never imply guest authentication", delegate
                {
                    var fake = new FakeRuntime();
                    string status = Output.Human(ResultData.Parse(Broker.Execute(RequestFor("status", "SAFE-DC"), fake)));
                    Assert(status.Contains("VM: SAFE-DC") && status.Contains("NOT ATTEMPTED") && status.Contains("VIX 8"));
                    string probe = Output.Human(ResultData.Parse(Broker.Execute(RequestFor("probe"), fake)));
                    Assert(probe.Contains("local host connection succeeded") && probe.Contains("NOT TESTED"));
                });
                Test("human cancel timeout and access violation are distinct, unknown is not success", delegate
                {
                    string cancel = Output.Human(ResultData.Error("user_cancelled", Stage.CredentialPromptReturned));
                    Assert(cancel.StartsWith("Cancelled", StringComparison.Ordinal) && !cancel.Contains("succeeded"));
                    var crash = Supervisor.Classify(null, 0xC0000005, Stage.GuestLogin, false, false, false);
                    string text = Output.Human(crash.Result);
                    Assert(crash.ExitCode == 4 && text.Contains("0xC0000005") && text.Contains("access violation") && text.Contains("UNKNOWN") && text.Contains("does NOT establish a password error"));
                    var timeout = Supervisor.Classify(null, 124, Stage.GuestLoginWait, false, false, false);
                    Assert(timeout.ExitCode == 124 && Output.Human(timeout.Result).Contains("deadline expired"));
                    var aborted = Supervisor.Classify(null, 125, Stage.GuestProgramWait, false, true, false);
                    Assert(aborted.ExitCode == 125 && Output.Human(aborted.Result).StartsWith("Cancelled", StringComparison.Ordinal) && aborted.Result.Outcome == "unknown");
                    Assert(Supervisor.Classify(null, 0, Stage.Complete, false, false, false).Result.ErrorCode == "no_worker_result");
                });
                Test("plain output wraps safely at 80 columns without colors or secret arguments", delegate
                {
                    var result = ResultData.Error("vm_identity_changed_reenroll_required", Stage.TargetValidate);
                    result.Target = "A" + new string('B', 47);
                    string text = Output.Human(result);
                    foreach (string line in text.Split('\n')) Assert(line.TrimEnd('\r').Length <= 80);
                    Assert(!text.Contains("\u001b") && !text.StartsWith("{", StringComparison.Ordinal));
                });
                Test("safe result protocol refuses unknown error strings and blank success", delegate
                {
                    Reject(delegate { ResultData.Parse("{\"ok\":false,\"error\":\"SYNTHETIC-SECRET\"}"); }, "worker_protocol_failed");
                    Reject(delegate { ResultData.Parse("{\"ok\":true}"); }, "worker_protocol_failed");
                    Reject(delegate { ResultData.Parse("{\"ok\":true,\"credential\":\"stored|validated_not_stored\"}"); }, "worker_protocol_failed");
                    Reject(delegate { ResultData.Parse("{\"ok\":true,\"nativeHostConnect\":false}"); }, "worker_protocol_failed");
                    Assert(ResultData.AllowedError("vix_error_3024") && !ResultData.AllowedError("vix_error_999999") && !ResultData.AllowedError("invalid_request|user_cancelled"));
                });
                Test("JSON is explicit and roundtrips a narrow public result", delegate
                {
                    var result = ResultData.Parse(Broker.Execute(RequestFor("status", "SAFE-DC"), new FakeRuntime()));
                    Assert(ResultData.Parse(result.Json()).Target == "SAFE-DC");
                    var old = Console.Out; var output = new StringWriter();
                    try { Console.SetOut(output); Assert(Program.Main(new[] { "bad", "SYNTHETIC-SECRET", "--json" }) == 2); }
                    finally { Console.SetOut(old); }
                    Assert(output.ToString().StartsWith("{", StringComparison.Ordinal) && !output.ToString().Contains("SYNTHETIC-SECRET"));
                });
                Test("CredUI cancellation and native error mapping are synthetic and single-attempt", delegate
                {
                    int calls = 0;
                    GuestCredential.PromptCall cancel = delegate (ref Native.CredUi ui, ref uint package, ref IntPtr blob, ref uint bytes, ref int save, uint flags)
                    {
                        calls++; Assert(blob == IntPtr.Zero && bytes == 0 && package == 0 && save == 0 && flags == 1);
                        Assert(ui.Size == 20 && ui.Message.Contains("SAFE-DC") && ui.Message.Contains(new string('1', 32)));
                        return 1223;
                    };
                    Reject(delegate { GuestCredential.PromptCore(Synthetic("SAFE-DC", '1'), false, cancel); }, "user_cancelled");
                    Assert(calls == 1 && Diagnostics.Failure == Stage.CredentialPromptReturned);
                    Assert(GuestCredential.PromptError(87) == "credential_prompt_invalid_parameter" && GuestCredential.PromptError(1004) == "credential_prompt_invalid_flags" && GuestCredential.PromptError(1312) == "credential_prompt_no_logon_session" && GuestCredential.PromptError(99999) == "credential_prompt_failed");
                });
                Test("failure stage survives normal cleanup stages", delegate
                {
                    Diagnostics.At(Stage.GuestLoginWait);
                    var error = new BrokerError("vix_error_3024");
                    Diagnostics.At(Stage.SecretCleanup);
                    ResultData result = ResultData.Error(error.Code, Diagnostics.Failure ?? Diagnostics.Current);
                    Assert(result.StageName == "guest_login_wait");
                });
                Test("supervisor receives only control results; worker stdout stderr discarded", delegate
                {
                    var r = Fixture("fixture-output");
                    Assert(r.ExitCode == 0 && r.Result.Registration == "saved" && !r.Result.Json().Contains("SYNTHETIC-OUTPUT"));
                });
                Test("supervisor reports synthetic AV exit without creating a real crash or dump", delegate
                {
                    var r = Fixture("fixture-crash");
                    Assert(r.ExitCode == 4 && r.Result.NativeExit == "0xC0000005" && r.Result.StageName == "guest_login_call" && r.Result.Outcome == "unknown");
                });
                Test("supervisor suppresses an apparent success if worker dies afterwards", delegate
                {
                    var r = Fixture("fixture-late-crash");
                    Assert(r.ExitCode == 4 && !r.Result.Ok && r.Result.Outcome == "unknown" && r.Result.StageName == "worker_exit");
                });
                Test("supervisor reports synthetic watchdog timeout, not password failure", delegate
                {
                    var r = Fixture("fixture-timeout");
                    Assert(r.ExitCode == 124 && r.Result.ErrorCode == "native_timeout" && r.Result.StageName == "guest_login_wait");
                });
                Test("supervisor independently bounds native worker stall", delegate
                {
                    var r = Fixture("fixture-stall", 500);
                    Assert(r.ExitCode == 124 && r.Result.ErrorCode == "native_timeout");
                });
                Test("returned official CLI deadline preserves structured cause and CLI stage even when worker exits124 after complete", delegate
                {
                    var returned = ResultData.Error("official_cli_timeout", Stage.CliCall); returned.Outcome = "unknown";
                    SupervisedResult result = Supervisor.Classify(returned, 124, Stage.Complete, false, false, false);
                    Assert(result.ExitCode == 124 && !result.Result.Ok && result.Result.ErrorCode == "official_cli_timeout" && result.Result.StageName == "cli_call" && result.Result.Outcome == "unknown");
                    Assert(Output.Human(result.Result).Contains("Official CLI deadline") && !Output.Human(result.Result).Contains("Native deadline expired"));
                    Assert(Supervisor.Classify(null, 124, Stage.CliCall, false, false, false).Result.ErrorCode == "native_timeout");
                    var success = new ResultData { Ok = true, Registration = "saved" };
                    Assert(!Supervisor.Classify(success, 124, Stage.Complete, false, false, false).Result.Ok);
                });
                Test("outer deadline cancellation and protocol failure override a returned CLI deadline", delegate
                {
                    var returned = ResultData.Error("official_cli_timeout", Stage.CliCall); returned.Outcome = "unknown";
                    Assert(Supervisor.Classify(returned, 124, Stage.Complete, true, false, false).Result.ErrorCode == "native_timeout");
                    Assert(Supervisor.Classify(returned, 124, Stage.Complete, false, true, false).Result.ErrorCode == "operation_cancelled");
                    Assert(Supervisor.Classify(returned, 124, Stage.Complete, false, false, true).Result.ErrorCode == "worker_protocol_failed");
                });
                Test("real synthetic nested CLI timeout traverses worker framing and remains official_cli_timeout rather than worker_exit", delegate
                {
                    SupervisedResult result = Fixture("fixture-cli-timeout");
                    Assert(result.ExitCode == 124 && result.Result.ErrorCode == "official_cli_timeout" && result.Result.StageName == "cli_call" && result.Result.Outcome == "unknown" && !result.Result.Ok);
                });
                Test("user wait pauses child watchdog and supervisor deadline without UI", delegate
                {
                    var r = Fixture("fixture-user-wait", 500);
                    Assert(r.ExitCode == 2 && r.Result.ErrorCode == "user_cancelled");
                });
                Test("supervisor rejects malformed control frames without forwarding raw data", delegate
                {
                    var r = Fixture("fixture-protocol");
                    Assert(r.ExitCode == 4 && r.Result.ErrorCode == "worker_protocol_failed" && !r.Result.Json().Contains("SYNTHETIC-OUTPUT"));
                });
                Test("all 47 installed commands have unique catalog rows and exact parser roundtrip", delegate
                {
                    Assert(Catalog.Entries.Count == 47); int active = 0;
                    foreach (CatalogEntry entry in Catalog.Entries)
                    {
                        VmrunRequest command = SampleCommand(entry.Name);
                        if (!(command.Entry.Name == entry.Name && VmrunRequest.Parse(command.Tokens()).Entry.Name == entry.Name)) throw new Exception("catalog parser roundtrip failed for " + entry.Name);
                        Request envelope = RequestFor(Prepend("vmrun", command.Tokens()));
                        if (envelope.Vmrun.Entry.Name != entry.Name) throw new Exception("catalog envelope mismatch for " + entry.Name);
                        if (Request.Parse(envelope.WorkerArguments()).Vmrun.Entry.Name != entry.Name) throw new Exception("catalog worker roundtrip failed for " + entry.Name);
                        if (entry.Enabled) { active++; if (entry.Backend == "native-vix" || entry.Backend == "native-vix-helper") { if (NativePlans.Symbol(command) != entry.Exports.Split(',')[0]) throw new Exception("catalog native symbol mismatch for " + entry.Name); } else if (!(Catalog.CliCommand(entry.Name) || entry.Backend == "official-https" && entry.Name == "downloadPhotonVM")) throw new Exception("catalog backend mismatch for " + entry.Name); }
                        else Reject(delegate { NativePlans.Symbol(command); }, "catalog_operation_unavailable");
                        bool liveBounded = Array.IndexOf(new[] { "runScriptInGuest", "listHostNetworks", "upgradevm", "killProcessInGuest", "deleteFileInGuest", "deleteDirectoryInGuest", "renameFileInGuest", "directoryExistsInGuest", "createDirectoryInGuest", "CreateTempfileInGuest", "listDirectoryInGuest", "runProgramInGuest", "fileExistsInGuest", "start", "reset", "deleteSnapshot", "revertToSnapshot", "connectNamedDevice", "disconnectNamedDevice", "readVariable", "writeVariable", "listSnapshots", "checkToolsState", "listPortForwardings", "stop", "suspend", "pause", "unpause", "snapshot", "setSharedFolderState", "addSharedFolder", "removeSharedFolder", "enableSharedFolders", "disableSharedFolders", "listProcessesInGuest", "CopyFileFromHostToGuest", "CopyFileFromGuestToHost" }, entry.Name) >= 0;
                        string expectedLive = OwnedForwarding.Command(entry.Name) ? "NOT RUN" : "PARENT_LIVE_BOUNDED";
                         if (!entry.Live.StartsWith(expectedLive, StringComparison.Ordinal) || !entry.Synthetic.StartsWith("PASS", StringComparison.Ordinal)) throw new Exception("catalog evidence status mismatch for " + entry.Name);
                    }
                    Assert(active == 47);
                });
                Test("frozen installed help matches catalog, added or missing command fails coverage", delegate
                {
                    string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "coverage", "installed-vmrun-help.txt");
                    string help = File.ReadAllText(file);
                    var expected = new HashSet<string>(); foreach (CatalogEntry entry in Catalog.Entries) expected.Add(entry.Name);
                    Assert(expected.SetEquals(Catalog.CommandsFromHelp(help)));
                    Assert(!expected.SetEquals(Catalog.CommandsFromHelp("newFutureCommand    args\n" + help)));
                    Assert(!expected.SetEquals(Catalog.CommandsFromHelp(help.Replace("start                    ", "removedStart             "))));
                });
                Test("every active catalog operation routes its declared mock backend with correct auth and scope", delegate
                {
                    foreach (CatalogEntry entry in Catalog.Entries)
                    {
                        if (!entry.Enabled) continue;
                        var runtime = new FakeRuntime(); VmrunRequest command = SampleCommand(entry.Name);
                        if (entry.TargetScoped) Grant(runtime, "TEST-VM", entry.Name);
                        if (HostOperations.Command(entry.Name)) runtime.HostAllowed = true;
                        ResultData result = ResultData.Parse(CatalogEngine.Execute(command, runtime));
                        Assert(result.Ok && result.Operation.Command == entry.Name && result.Operation.Backend == entry.Backend);
                        Assert(runtime.Events.Contains("login") == command.NeedsCredential);
                        Assert((runtime.Events.Contains("operation-consent") || runtime.Events.Contains("host-read-consent")) == entry.NeedsConsent);
                        if (entry.TargetScoped) Assert(result.Target == "TEST-VM" && runtime.Events.Contains((entry.Backend == "native-vix" || entry.Backend == "native-vix-helper" ? "operation:" : "official-cli:") + entry.Name));
                        Assert(runtime.LiveSessions == 0);
                    }
                });
                Test("all 47 catalog names now have bounded backends and none is an unimplemented refusal stub", delegate
                {
                    int gated = 0;
                    foreach (CatalogEntry entry in Catalog.Entries)
                    {
                        if (entry.Enabled) continue; gated++;
                        var runtime = new FakeRuntime(); VmrunRequest command = SampleCommand(entry.Name);
                        Reject(delegate { CatalogEngine.Execute(command, runtime); }, "catalog_operation_unavailable");
                        Assert(runtime.Events.Count == 0 && runtime.Credential == null && runtime.Selected.Count == 0);
                    }
                    Assert(gated == 0);
                });
                Test("catalog mutations require disposable policy and exact individual command grant", delegate
                {
                    var runtime = new FakeRuntime(); VmrunRequest command = SampleCommand("reset");
                    Reject(delegate { CatalogEngine.Execute(command, runtime); }, "disposable_target_required");
                    Assert(!runtime.Events.Contains("connect") && runtime.Credential == null);
                    Target target = runtime.Resolve("TEST-VM"); CapabilityProfile profile = CapabilityProfile.Default(target); profile.Disposable = true;
                    runtime.Policies[target.Binding] = profile;
                    Reject(delegate { CatalogEngine.Execute(command, runtime); }, "capability_not_granted");
                    Assert(!runtime.Events.Contains("connect"));
                    profile.Commands.Add("reset");
                    Assert(ResultData.Parse(CatalogEngine.Execute(command, runtime)).Operation.Completion == "native_completed_not_verified");
                });
                Test("configured native execution never calls approval UI even when a legacy callback would reject", delegate
                {
                    var runtime = new FakeRuntime { Consent = false }; Grant(runtime, "TEST-VM", "runProgramInGuest");
                    Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime)).Ok);
                    Assert(!runtime.Events.Contains("operation-consent") && runtime.Events.Contains("vault") && runtime.Events.Contains("login") && runtime.Events.Contains("operation:runProgramInGuest") && runtime.LiveSessions == 0);
                });
                Test("policy revocation at preparation checkpoint stops before credential retrieval with no approval phase", delegate
                {
                    var runtime = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(runtime, "TEST-VM", "runProgramInGuest");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime); }, "capability_policy_changed");
                    Assert(!runtime.Events.Contains("vault") && !runtime.Events.Contains("login"));
                });
                Test("catalog grants and credentials never cross registered VM identities", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "SAFE-DC", "listProcessesInGuest");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("listProcessesInGuest"), runtime); }, "capability_not_granted");
                    Grant(runtime, "TEST-VM", "listProcessesInGuest");
                    runtime.CrossCredential = true;
                    var tokens = SampleCommand("listProcessesInGuest").Tokens(); tokens[1] = "SAFE-DC";
                    Reject(delegate { CatalogEngine.Execute(VmrunRequest.Parse(tokens), runtime); }, "credential_target_mismatch");
                    Assert(!runtime.Events.Contains("login") && runtime.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("all host-network writes still need machine policy regardless of any per-VM disposable grant", delegate
                {
                    foreach (string name in new[] { "setPortForwarding", "deletePortForwarding" })
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "reset");
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "forward_policy_required");
                        Assert(!runtime.Events.Contains("connect") && runtime.Selected.Count == 0 && runtime.Credential == null);
                    }
                });
                Test("public-share and native-transfer grammar reject arbitrary imported host or guest paths", delegate
                {
                    // Requirement change: transfers use normal trusted VIX semantics,
                    // not a sandbox. Caller path imports still are NOT authorized.
                    foreach (string attack in new[] { @"..\..\outside", @"C:\junction\outside", @"C:\Users\test\.ssh\id_rsa", @"C:\Windows\System32\config\SAM", @"C:\existing.txt:stream", @"\\server\secret" })
                    {
                        Reject(delegate { VmrunRequest.Parse(new[] { "addSharedFolder", "TEST-VM", attack }); }, "public_share_not_approved");
                        Reject(delegate { VmrunRequest.Parse(new[] { "CopyFileFromHostToGuest", "TEST-VM", "public", attack }); }, "guest_fixture_generated_refused");
                        Reject(delegate { VmrunRequest.Parse(new[] { "CopyFileFromGuestToHost", "TEST-VM", "public", attack, "32" }); }, "transfer_request_invalid");
                    }
                });
                Test("unapproved program aliases and unsafe paths fail without host filesystem access", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "runProgramInGuest");
                    runtime.Policies[runtime.Resolve("TEST-VM").Binding].Programs.Clear();
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime); }, "program_not_approved");
                    Assert(!runtime.Events.Contains("connect") && runtime.Credential == null);
                    foreach (string path in new[] { @"..\cmd.exe", @"\\host\cmd.exe", @"C:\x\..\cmd.exe", @"C:\x\cmd.exe:stream", @"C:\x.\cmd.exe", @"C:\x\cmd.exe " }) Assert(!CapabilityProfile.ValidProgramPath(path));
                });
                Test("execution flags do not silently enable noWait or interactive contexts", delegate
                {
                    foreach (string option in new[] { "-noWait", "-activeWindow", "-interactive" })
                        Reject(delegate { VmrunRequest.Parse(new[] { "runProgramInGuest", "TEST-VM", option, "tool" }); }, "unsupported_operation_option");
                    Reject(delegate { RequestFor("vmrun", "runProgramInGuest", "TEST-VM", "tool", "--", "--password=synthetic"); }, "secret_argument_forbidden");
                    Reject(delegate { RequestFor("vmrun", "stop", "TEST-VM"); }, "invalid_request");
                });
                Test("guest literal output flags survive separator; broker flags are before separator", delegate
                {
                    Request request = RequestFor("vmrun", "runProgramInGuest", "TEST-VM", "tool", "--stored", "--json", "--diagnostic", "--", "--json", "--diagnostic", "two words", "字");
                    Assert(request.Json && request.Diagnostic && request.Vmrun.Stored);
                    Assert(request.Vmrun.Arguments[1] == "--json" && request.Vmrun.Arguments[2] == "--diagnostic");
                    Request replay = Request.Parse(request.WorkerArguments());
                    Assert(!replay.Json && !replay.Diagnostic && replay.Vmrun.Arguments[1] == "--json" && replay.Vmrun.Arguments[4] == "字");
                });
                Test("Windows quoting roundtrips Unicode spaces quotes empty args and literal metacharacters without shell", delegate
                {
                    var result = Supervisor.RunCore(typeof(Tests).Assembly.Location, new[] { "fixture-arguments", "two words", "Ω字", "a\"b", "trail\\", "&|<>%^!", "" }, false, 3000);
                    Assert(result.ExitCode == 0 && result.Result.Registration == "saved");
                    Assert(WindowsArguments.Quote("a b\\") == "\"a b\\\\\"");
                });
                Test("native plans bind exact mode flags without implicit hard-power defaults", delegate
                {
                    Assert(NativePlans.Flags(VmrunRequest.Parse(new[] { "start", "TEST-VM", "gui" })) == 512);
                    Assert(NativePlans.Flags(VmrunRequest.Parse(new[] { "start", "TEST-VM", "nogui" })) == 0);
                    foreach (string name in new[] { "stop", "reset", "suspend" })
                    { Assert(NativePlans.Flags(VmrunRequest.Parse(new[] { name, "TEST-VM", "soft" })) == 4); Assert(NativePlans.Flags(VmrunRequest.Parse(new[] { name, "TEST-VM", "hard" })) == 0); }
                    Assert(NativePlans.Flags(VmrunRequest.Parse(new[] { "deleteSnapshot", "TEST-VM", "s", "andDeleteChildren" })) == 1);
                    Assert(VmrunRequest.Parse(new[] { "clone", "TEST-VM", "full" }).Entry.Name == "clone");
                    foreach (string mode in new[] { "full", "linked" }) Reject(delegate { VmrunRequest.Parse(new[] { "clone", "TEST-VM", @"D:\Scratch\new.vmx", mode }); }, "invalid_request");
                    Reject(delegate { VmrunRequest.Parse(new[] { "clone", "TEST-VM", "linked" }); }, "invalid_request");
                    foreach (string mode in new[] { "writable", "readonly" })
                    { Assert(VmrunRequest.Parse(new[] { "setSharedFolderState", "TEST-VM", "s", mode }).Entry.State == "partial"); Reject(delegate { VmrunRequest.Parse(new[] { "setSharedFolderState", "TEST-VM", "s", @"D:\Scratch", mode }); }, "invalid_request"); }
                    Reject(delegate { VmrunRequest.Parse(new[] { "runScriptInGuest", "TEST-VM", "-interactive", "-activeWindow", "-noWait", "interpreter", "synthetic" }); }, "unsupported_operation_option");
                });
                Test("bulk registered metadata preserves per-VM failures without global false success", delegate
                {
                    var runtime = new FakeRuntime { BadTargetName = "TEST-VM" };
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand("list"), runtime));
                    Assert(!result.Ok && result.ErrorCode == "partial_vm_failure" && result.Operation.Failures == 1 && result.Operation.Rows.Count == 2);
                    Assert(result.Operation.Rows[0].Power == 8 && result.Operation.Rows[1].Error == "vm_identity_changed_reenroll_required");
                    Assert(Output.Human(result).Contains("Per-VM failures: 1") && !runtime.Events.Contains("login"));
                    Assert(Supervisor.Classify(result, 2, Stage.Complete, false, false, false).ExitCode == 2);
                });
                Test("catalog results suppress guest owners command lines environment and raw snapshot labels", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "listProcessesInGuest");
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand("listProcessesInGuest"), runtime));
                    string text = result.Json(); Assert(result.Operation.Count == 3 && !text.Contains("UserName") && !text.Contains("Password") && !text.Contains("commandLine"));
                    var invalid = OperationReport.New(SampleCommand("listSnapshots")); invalid.SnapshotRefs = new List<string> { "SECRET-label" };
                    Reject(invalid.Validate, "worker_protocol_failed");
                    invalid = OperationReport.New(SampleCommand("listProcessesInGuest")); invalid.Count = 257;
                    Reject(invalid.Validate, "worker_protocol_failed");
                });
                Test("private sidecar policies roundtrip and cannot alter version-2 credential keys", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target a = Synthetic("SAFE-DC", '1'), b = Synthetic("TEST-VM", '2'); store.Add(a); store.Add(b);
                        string key = store.Read().Resolve(a.Name).CredentialKey;
                        CapabilityProfile profile = CapabilityProfile.Default(a); profile.Disposable = true; profile.Commands.Add("reset"); profile.Revision = new string('A', 32);
                        store.WritePolicy(a, profile);
                        Assert(store.ReadPolicy(a).Commands.Contains("reset") && !store.ReadPolicy(b).Disposable && store.Read().Resolve(a.Name).CredentialKey == key);
                        Target changed = a.Clone(); changed.Generation = new string('3', 32);
                        Assert(!store.ReadPolicy(changed).Disposable);
                        string file = Path.Combine(root, "policy-" + a.Binding + ".json"); File.WriteAllText(file, "not-json");
                        Reject(delegate { store.ReadPolicy(a); }, "capability_policy_invalid");
                    });
                });
                Test("catalog and native operation reports survive bounded supervisor framing", delegate
                {
                    string catalog = Broker.Execute(RequestFor("catalog"), new FakeRuntime());
                    Assert(catalog.Length < 12000 && ResultData.Parse(catalog).CatalogIndex.Count == 47);
                    foreach (CatalogEntry entry in Catalog.Entries) { string detail = Broker.Execute(RequestFor("catalog", entry.Name), new FakeRuntime()); Assert(detail.Length < 32768 && ResultData.Parse(detail).CatalogRows.Count == 1); }
                    Assert(Output.Human(ResultData.Parse(catalog)).Contains("NOT full implementation"));
                    string details = Broker.Execute(RequestFor("catalog", "clone"), new FakeRuntime());
                    Assert(Output.Human(ResultData.Parse(details)).Contains("CLONE-1"));
                    Reject(delegate { RequestFor("vmrun", "unknown-native-command", "SAFE-DC"); }, "invalid_request");
                });
                Test("generic environment and runtime variable reads are gated before credentials", delegate
                {
                    foreach (string[] variableArgs in new[] { new[] { "readVariable", "TEST-VM", "guestEnv", "PASSWORD", "--stored" }, new[] { "readVariable", "TEST-VM", "runtimeConfig", "uuid.bios" } })
                    {
                        var runtime = new FakeRuntime();
                        Reject(delegate { CatalogEngine.Execute(VmrunRequest.Parse(variableArgs), runtime); }, "catalog_operation_unavailable");
                        Assert(runtime.Events.Count == 0);
                    }
                });
                Test("nonzero guest program exit is an error, not successful configuration", delegate
                {
                    var runtime = new FakeRuntime { GuestProgramExit = 7 }; Grant(runtime, "TEST-VM", "runProgramInGuest");
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime));
                    Assert(!result.Ok && result.ErrorCode == "guest_program_failed" && result.Operation.GuestExit == 7);
                    Assert(Output.Human(result).Contains("Stdout/stderr NOT captured") && Supervisor.Classify(result, 2, Stage.Complete, false, false, false).ExitCode == 2);
                });
                Test("native non-secret text buffers are terminated and owned independently of managed temporary arrays", delegate
                {
                    using (var text = Vix.CopyNonSecretText("Ω字 \"quoted\""))
                    {
                        byte[] expected = Encoding.UTF8.GetBytes("Ω字 \"quoted\"");
                        Assert(text.Size == expected.Length + 1 && Marshal.ReadByte(text.Pointer, expected.Length) == 0);
                        for (int i = 0; i < expected.Length; i++) Assert(Marshal.ReadByte(text.Pointer, i) == expected[i]);
                    }
                });
                Test("failed policy publication preserves previous permissions and registry", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target a = Synthetic("SAFE-DC", '1'); store.Add(a);
                        CapabilityProfile old = CapabilityProfile.Default(a); store.WritePolicy(a, old);
                        var failing = new RegistryStore(root, delegate { throw new IOException("synthetic publication failure"); });
                        CapabilityProfile changed = CapabilityProfile.Default(a); changed.Disposable = true; changed.Commands.Add("reset"); changed.Revision = new string('B', 32);
                        bool failed = false; try { failing.WritePolicy(a, changed); } catch (IOException) { failed = true; }
                        Assert(failed && !store.ReadPolicy(a).Disposable && store.Read().Resolve(a.Name).Binding == a.Binding && Directory.GetFiles(root, "policy.new.*").Length == 0);
                    });
                });
                Test("policy fingerprint detects changed grants even if revision was not changed", delegate
                {
                    var runtime = new FakeRuntime { MutatePolicyAtPrepare = true }; Grant(runtime, "TEST-VM", "runProgramInGuest");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime); }, "capability_policy_changed");
                    Assert(!runtime.Events.Contains("vault") && !runtime.Events.Contains("login"));
                });
                Test("credential-free CLI plans use exact tools/argument arrays and never auth flags", delegate
                {
                    Target target = Synthetic("TEST-VM", '2');
                    foreach (string name in new[] { "getGuestIPAddress", "listHostNetworks", "listPortForwardings", "connectNamedDevice", "disconnectNamedDevice", "captureScreen" })
                    {
                        VmrunRequest request = SampleCommand(name);
                        CliPlan plan = CliPlan.Build(request, request.Entry.TargetScoped ? target : null, name == "captureScreen" ? @"D:\SyntheticPrivate\screen.png" : null);
                        foreach (string token in plan.Arguments) Assert(token != "-gp" && token != "-gu" && token != "-vp" && token != "--verbose");
                        Assert(plan.ReadOutput == (name == "getGuestIPAddress" || name == "listHostNetworks" || name == "listPortForwardings"));
                        Assert((plan.Tool == OfficialTool.Vmcli) == (name == "captureScreen"));
                    }
                    Reject(delegate { CliPlan.Build(SampleCommand("runProgramInGuest"), target, null); }, "cli_plan_forbidden");
                });
                Test("host inventory executes under the fixed local read scope without UI and cannot authorize writes", delegate
                {
                    foreach (string name in new[] { "listHostNetworks", "listPortForwardings" })
                    {
                        var runtime = new FakeRuntime { Consent = false }; Grant(runtime, "TEST-VM", "reset");
                        ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand(name), runtime));
                        Assert(result.Target == null && result.Operation.Backend == "official-vmrun-cli" && !runtime.Events.Contains("connect") && !runtime.Events.Contains("vault") && !runtime.Events.Contains("host-read-consent"));
                        Reject(delegate { OperationAuthorization.HostRead(SampleCommand("setPortForwarding")); }, "catalog_operation_unavailable");
                        CapabilityProfile invalid = CapabilityProfile.Default(runtime.Resolve("TEST-VM")); invalid.Commands.Add(name);
                        Reject(delegate { invalid.Validate(runtime.Resolve("TEST-VM")); }, "capability_policy_invalid");
                    }
                });
                Test("IP parser accepts only complete literal addresses and refuses raw errors", delegate
                {
                    Assert(CliParsing.Address("192.0.2.42") == "192.0.2.42" && CliParsing.Address("2001:db8::1") == "2001:db8::1");
                    foreach (string invalid in new[] { "localhost", "127.1", "2130706433", " 192.0.2.1", "192.0.2.1\nprivate", "fe80::1%12", "Error: SYNTHETIC-PRIVATE" }) Reject(delegate { CliParsing.Address(invalid); }, "cli_output_unrecognized");
                    using (var reply = new CliReply { Exit = 1, Output = Encoding.UTF8.GetBytes("SYNTHETIC-PRIVATE") }) Reject(delegate { CliParsing.Parse(SampleCommand("getGuestIPAddress"), reply); }, "official_cli_failed");
                });
                Test("strict host parsers return bounded public fields and suppress private descriptions", delegate
                {
                    using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes("Total networks: 2\nName Type Subnet\nvmnet0 bridged SYNTHETIC-PRIVATE\nvmnet1 host-only SYNTHETIC-PRIVATE\n") })
                    { OperationReport report = CliParsing.Parse(SampleCommand("listHostNetworks"), reply); report.Validate(); Assert(report.Count == 2 && report.Inventory[1].Kind == "host-only" && !new ResultData { Ok = true, Operation = report }.Json().Contains("SYNTHETIC-PRIVATE")); }
                    using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes("Total port forwardings: 1\nProtocol HostPort GuestIP GuestPort Description\ntcp 12345 192.0.2.42 443 SYNTHETIC-PRIVATE\n") })
                    { OperationReport report = CliParsing.Parse(SampleCommand("listPortForwardings"), reply); report.Validate(); Assert(report.Inventory[0].HostPort == 12345 && report.Inventory[0].Address == "192.0.2.42"); }
                    foreach (string malformed in new[] { "Error: network vmnet1 missing", "vmnet1 unsupported private", "Total networks: 2\nvmnet1 nat\n", "Total networks: 2\nvmnet1 nat\nvmnet1 nat\n" })
                        using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(malformed) }) Reject(delegate { CliParsing.Parse(SampleCommand("listHostNetworks"), reply); }, "cli_output_unrecognized");
                });
                Test("bounded CLI runner isolates a synthetic process and does not capture stderr", delegate
                {
                    Assert(Marshal.SizeOf(typeof(Native.JobBasicLimits)) == 48 && Marshal.SizeOf(typeof(Native.JobLimits)) == 112);
                    using (CliReply reply = BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "ip" }, true, 3000, 1024, null))
                    { Assert(reply.Exit == 0 && Encoding.UTF8.GetString(reply.Output).Trim() == "192.0.2.42" && !Encoding.UTF8.GetString(reply.Output).Contains("SYNTHETIC-PRIVATE")); }
                    using (CliReply reply = BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "ip" }, false, 3000, 1024, null)) Assert(reply.Output.Length == 0);
                });
                Test("bounded CLI timeout output and file limits kill only the synthetic direct child", delegate
                {
                    Reject(delegate { using (BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "stall" }, true, 200, 1024, null)) { } }, "official_cli_timeout");
                    Reject(delegate { using (BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "flood" }, true, 3000, 1024, null)) { } }, "cli_output_limit");
                    Reject(delegate { using (BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "stall" }, false, 3000, 1024, delegate { return false; })) { } }, "private_export_limit");
                });
                Test("private export root is handle-bound, not a path-prefix allowlist", delegate
                {
                    string directory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "export-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
                    try
                    {
                        ExportRoot root = ExportRoot.Capture(directory);
                        using (var pin = PinnedDirectory.Open(directory))
                        {
                            Assert(pin.Identity == root.Identity);
                            bool blocked = false; try { Directory.Move(directory, directory + "-renamed"); } catch (IOException) { blocked = true; }
                            Assert(blocked);
                        }
                        foreach (string invalid in new[] { @"D:\", @"D:\x\..\y", @"D:\x.\y", @"\\server\x", @"D:\x:ads" }) Reject(delegate { HostPaths.ApprovedRoot(invalid); }, "export_root_invalid");
                    }
                    finally { if (Directory.Exists(directory)) Directory.Delete(directory); if (Directory.Exists(directory + "-renamed")) Directory.Delete(directory + "-renamed"); }
                });
                Test("private capture uses new protected reservation and validates only bounded PNG header", delegate
                {
                    string directory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "export-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
                    string file = null, captureDirectory = null, bucket = null;
                    try
                    {
                        ExportRoot root = ExportRoot.Capture(directory);
                        using (PrivateCapture capture = PrivateCapture.Create(Synthetic("TEST-VM", '2'), root))
                        {
                            file = capture.FilePath; captureDirectory = Path.GetDirectoryName(file); bucket = Path.GetDirectoryName(captureDirectory);
                            HostPaths.CheckPrivateDirectory(captureDirectory); Assert(capture.Id.Length == 32 && new FileInfo(file).Length == 0);
                            using (CliReply reply = BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "png", file }, false, 3000, 1024, capture.WithinLimit)) Assert(reply.Exit == 0);
                            Assert(capture.ValidateCompleted() == 128);
                            bool blocked = false; try { File.Delete(file); } catch (IOException) { blocked = true; }
                            Assert(blocked);
                        }
                        Assert(Directory.GetFiles(directory).Length == 0); // No caller-controlled root filename.
                    }
                    finally { if (file != null && File.Exists(file)) File.Delete(file); if (captureDirectory != null && Directory.Exists(captureDirectory)) Directory.Delete(captureDirectory); if (bucket != null && Directory.Exists(bucket)) Directory.Delete(bucket); Directory.Delete(directory); }
                });
                Test("capture refuses caller output paths, missing root grants and invalid PNG payloads", delegate
                {
                    Reject(delegate { RequestFor("vmrun", "captureScreen", "TEST-VM", @"C:\existing.png"); }, "invalid_request");
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "captureScreen"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].Export = null;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("captureScreen"), runtime); }, "export_root_not_approved");
                    Assert(!runtime.Events.Contains("official-cli:captureScreen"));
                    Reject(delegate { PrivateCapture.ValidatePngHeader(new byte[24]); }, "private_export_invalid");
                });
                Test("device parser never reads VNC keys and only accepts explicit optical IDs", delegate
                {
                    string descriptor = "RemoteDisplay.vnc.key = \"SYNTHETIC-PRIVATE\"\nsata0:1.deviceType = \"cdrom-image\"\nsata0:1.present = \"TRUE\"\nsata0:1.fileName = \"D:\\Media\\fixture.iso\"\n";
                    using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(descriptor)))
                    { Assert(DeviceBinding.Field(stream, "sata0:1.deviceType") == "cdrom-image"); Reject(delegate { DeviceBinding.Field(stream, "RemoteDisplay.vnc.key"); }, "device_not_approved"); }
                    foreach (string id in new[] { "ethernet0", "Ethernet0", "usb0", "sound", "serial0", "sata0:99", "sata0:1.fileName" }) Reject(delegate { DeviceBinding.Id(id); }, "device_not_approved");
                    Reject(delegate { RequestFor("vmrun", "connectNamedDevice", "TEST-VM", "ethernet0"); }, "device_not_approved");
                });
                Test("optical binding pins VMX descriptor and exact non-reparse ISO file identity", delegate
                {
                    string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optical-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
                    string iso = Path.Combine(root, "fixture.iso"), vmx = Path.Combine(root, "fixture.vmx");
                    try
                    {
                        File.WriteAllText(iso, "synthetic non-secret fixture, not a VM/real ISO");
                        string text = "uuid.bios = \"" + new string('1', 32) + "\"\nsata0:1.deviceType = \"cdrom-image\"\nsata0:1.present = \"TRUE\"\nsata0:1.fileName = \"" + iso + "\"\n";
                        File.WriteAllText(vmx, text); Target target = VmIdentity.Capture("SyntheticOptical", vmx);
                        ApprovedDevice approved = DeviceBinding.Capture(target, "sata0:1");
                        using (FileStream pin = DeviceBinding.Validate(target, approved)) Assert(pin.Length > 0);
                        File.WriteAllText(vmx, text.Replace("cdrom-image", "disk"));
                        Reject(delegate { using (DeviceBinding.Validate(target, approved)) { } }, "device_not_approved");
                    }
                    finally { File.Delete(vmx); File.Delete(iso); Directory.Delete(root); }
                });
                Test("new export/device fields are optional for existing version-1 capability profiles", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target target = Synthetic("SAFE-DC", '1'); store.Add(target);
                        CapabilityProfile old = CapabilityProfile.Default(target); store.WritePolicy(target, old);
                        CapabilityProfile loaded = store.ReadPolicy(target);
                        Assert(loaded.Export == null && loaded.Devices == null && loaded.Fingerprint() == old.Fingerprint() && loaded.Binding == target.Binding);
                    });
                });
                Test("real synthetic junctions are rejected before export or media access", delegate
                {
                    string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "junction-" + Guid.NewGuid().ToString("N"));
                    string outside = root + "-outside", link = Path.Combine(root, "link"); Directory.CreateDirectory(root); Directory.CreateDirectory(outside);
                    try
                    {
                        // Test-only constant Windows utility and newly owned paths.
                        // No user path, VM, shell API, global config or credential input.
                        var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"), "/d /c mklink /J " + WindowsArguments.Quote(link) + " " + WindowsArguments.Quote(outside));
                        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
                        using (var process = System.Diagnostics.Process.Start(start))
                        { process.StandardOutput.ReadToEnd(); process.StandardError.ReadToEnd(); Assert(process.WaitForExit(5000) && process.ExitCode == 0); }
                        Reject(delegate { using (PinnedDirectory.Open(link)) { } }, "export_path_redirected");
                        Reject(delegate { ExportRoot.Capture(link); }, "export_path_redirected");
                    }
                    finally { if (Directory.Exists(link)) Directory.Delete(link); Directory.Delete(root); Directory.Delete(outside); }
                });
                Test("stage2 review refuses ambiguous header-only empty inventories", delegate
                {
                    foreach (string command in new[] { "listHostNetworks", "listPortForwardings" })
                    {
                        string header = command == "listHostNetworks" ? "Name Type\n" : "Protocol HostPort GuestIP GuestPort Description\n";
                        using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(header) }) Reject(delegate { CliParsing.Parse(SampleCommand(command), reply); }, "cli_output_unrecognized");
                        string total = command == "listHostNetworks" ? "Total networks: 0\n" : "Total port forwardings: 0\n";
                        using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(total) }) Assert(CliParsing.Parse(SampleCommand(command), reply).Count == 0);
                    }
                    using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes("Total networks: 0\n") }) Reject(delegate { CliParsing.Parse(SampleCommand("listPortForwardings"), reply); }, "cli_output_unrecognized");
                });
                Test("stage2 review checks PNG IHDR length and final owner-private ACL", delegate
                {
                    byte[] header = new byte[24]; byte[] signature = { 137, 80, 78, 71, 13, 10, 26, 10 }; Array.Copy(signature, header, 8);
                    header[12] = (byte)'I'; header[13] = (byte)'H'; header[14] = (byte)'D'; header[15] = (byte)'R'; header[19] = 1; header[23] = 1;
                    Reject(delegate { PrivateCapture.ValidatePngHeader(header); }, "private_export_invalid");
                    header[11] = 13; PrivateCapture.ValidatePngHeader(header);
                    string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "acl-" + Guid.NewGuid().ToString("N") + ".txt");
                    try
                    {
                        using (var stream = new FileStream(file, FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.ReadWrite, 4096, FileOptions.None, HostPaths.FileSecurity()))
                        {
                            HostPaths.CheckPrivateFile(file);
                            var security = File.GetAccessControl(file);
                            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"), System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow));
                            File.SetAccessControl(file, security);
                            Reject(delegate { HostPaths.CheckPrivateFile(file); }, "export_acl_rejected");
                        }
                    }
                    finally { File.Delete(file); }
                });
                Test("private script CLI accepts alias only, never raw code paths or interactive options", delegate
                {
                    Request request = RequestFor("vmrun", "runScriptInGuest", "TEST-VM", "script", "--stored", "--diagnostic");
                    Assert(request.Vmrun.Stored && request.Vmrun.Arguments.Length == 1 && request.Vmrun.Arguments[0] == "script");
                    Assert(String.Join(" ", request.WorkerArguments()) == "vmrun runScriptInGuest TEST-VM script --stored");
                    foreach (string option in new[] { "-noWait", "-interactive", "-activeWindow" }) Reject(delegate { RequestFor("vmrun", "runScriptInGuest", "TEST-VM", option, "script"); }, "unsupported_operation_option");
                    Reject(delegate { RequestFor("vmrun", "runScriptInGuest", "TEST-VM", @"C:\secret.ps1"); }, "invalid_request");
                    Reject(delegate { RequestFor("vmrun", "runScriptInGuest", "TEST-VM", "interpreter", "SYNTHETIC-CODE"); }, "invalid_request");
                    Assert(NativePlans.Symbol(request.Vmrun) == "VixVM_RunProgramInGuest");
                    Reject(delegate { CliPlan.Build(request.Vmrun, Synthetic("TEST-VM", '2'), null); }, "cli_plan_forbidden");
                });
                Test("script grants and identity checks precede private loading and credentials without an operation prompt", delegate
                {
                    var missing = new FakeRuntime(); Grant(missing, "TEST-VM", "runScriptInGuest"); missing.Policies[missing.Resolve("TEST-VM").Binding].Scripts.Clear();
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runScriptInGuest"), missing); }, "script_not_approved");
                    Assert(!missing.Events.Contains("connect") && missing.Credential == null);
                    var denied = new FakeRuntime { Consent = false }; Grant(denied, "TEST-VM", "runScriptInGuest");
                    DenyGrant(denied, "runScriptInGuest"); Reject(delegate { CatalogEngine.Execute(SampleCommand("runScriptInGuest"), denied); }, "capability_not_granted");
                    Assert(!denied.Events.Contains("prepare-private-inputs") && !denied.Events.Contains("vault") && !denied.Events.Contains("login"));
                    var changed = new FakeRuntime { ScriptChanged = true }; Grant(changed, "TEST-VM", "runScriptInGuest");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runScriptInGuest"), changed); }, "script_identity_changed");
                    Assert(!changed.Events.Contains("operation-consent") && changed.Events.Contains("prepare-private-inputs") && !changed.Events.Contains("vault") && !changed.Events.Contains("login"));
                });
                Test("private scripts pin exact UTF8 bytes file/root identity and hash without plaintext IPC", delegate
                {
                    WithCodeFixture(delegate (string root, string path)
                    {
                        string text = "# SYNTHETIC NON-SECRET CODE\nWrite-Output 'Ω字'\nexit 0\n"; File.WriteAllText(path, text, new UTF8Encoding(false));
                        ApprovedScript script = ApprovedScript.Enroll("fixture", path, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
                        using (PinnedScript pin = PinnedScript.Open(script, false))
                        {
                            Assert(pin.FileIdentity == script.FileIdentity && pin.Sha256 == script.Sha256 && Marshal.ReadByte(pin.Code) == '#');
                            bool blocked = false; try { File.WriteAllText(path, "changed"); } catch (IOException) { blocked = true; }
                            Assert(blocked);
                            byte[] expected = Encoding.UTF8.GetBytes(text); Assert(Marshal.ReadByte(pin.Code, expected.Length) == 0);
                        }
                        File.WriteAllText(path, text + "# changed\n", new UTF8Encoding(false));
                        Reject(delegate { using (PinnedScript.Open(script, false)) { } }, "script_identity_changed");
                        File.WriteAllText(path, text, new UTF8Encoding(false));
                        string replacement = path + ".new"; File.WriteAllText(replacement, text, new UTF8Encoding(false)); File.Replace(replacement, path, null);
                        Reject(delegate { using (PinnedScript.Open(script, false)) { } }, "script_identity_changed");
                    });
                });
                Test("PowerShell equivalent encodes exact pinned BOM-stripped Unicode as UTF16LE with fixed unattended flags and no policy override", delegate
                {
                    WithCodeFixture(delegate (string root, string path)
                    {
                        const string text = "# PUBLIC Ω字 supplementary 😀\r\n$literal = 'quotes & | > < ` \\\"'\r\nexit 7\r\n";
                        File.WriteAllText(path, text, new UTF8Encoding(true));
                        ApprovedScript script = ApprovedScript.Enroll("fixture", path, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
                        using (PinnedScript pin = PinnedScript.Open(script, false))
                        {
                            string arguments = Marshal.PtrToStringAnsi(pin.Arguments);
                            Assert(arguments.StartsWith(PinnedScript.ArgumentPrefix, StringComparison.Ordinal));
                            string encoded = arguments.Substring(PinnedScript.ArgumentPrefix.Length);
                            Assert(Encoding.Unicode.GetString(Convert.FromBase64String(encoded)) == text && !arguments.Contains("ExecutionPolicy") && !arguments.Contains("-File") && !arguments.Contains("Bypass") && !arguments.Contains("NoExit"));
                            Assert(!String.Join(" ", SampleCommand("runScriptInGuest").Tokens()).Contains(encoded));
                            var report = OperationReport.New(SampleCommand("runScriptInGuest")); report.GuestExit = 7; report.GuestExitPropertyType = 1; report.Validate();
                            string json = new ResultData { Ok = false, ErrorCode = "guest_program_failed", Operation = report }.Json();
                            Assert(report.ScriptCarrier == PinnedScript.Carrier && !json.Contains(encoded) && !json.Contains("supplementary") && !json.Contains(path));
                            report.ScriptCarrier = "native_vix_runscript"; Reject(report.Validate, "worker_protocol_failed");
                        }
                    });
                });
                Test("PowerShell encoded command enforces Windows commandline bound before credential access without truncation or appended exit0", delegate
                {
                    WithCodeFixture(delegate (string root, string path)
                    {
                        string interpreter = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                        File.WriteAllText(path, "#" + new string('x', PinnedScript.MaximumBytes - 1), new UTF8Encoding(false));
                        Reject(delegate { ApprovedScript.Enroll("fixture", path, interpreter); }, "script_size_rejected");
                        File.WriteAllText(path, "#" + new string('x', 7999) + "\nexit 19\n", new UTF8Encoding(false));
                        ApprovedScript script = ApprovedScript.Enroll("fixture", path, interpreter);
                        using (PinnedScript pin = PinnedScript.Open(script, false))
                        {
                            string arguments = Marshal.PtrToStringAnsi(pin.Arguments);
                            string decoded = Encoding.Unicode.GetString(Convert.FromBase64String(arguments.Substring(PinnedScript.ArgumentPrefix.Length)));
                            Assert(decoded.EndsWith("\nexit 19\n", StringComparison.Ordinal) && !decoded.Contains("exit 0") && WindowsArguments.Quote(interpreter).Length + arguments.Length + 2 <= 32767);
                        }
                    });
                });
                Test("script code size encoding terminators root and interpreter are validated", delegate
                {
                    WithCodeFixture(delegate (string root, string path)
                    {
                        string interpreter = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                        File.WriteAllText(path, new string('x', PinnedScript.MaximumBytes + 1), new UTF8Encoding(false));
                        Reject(delegate { ApprovedScript.Enroll("fixture", path, interpreter); }, "script_size_rejected");
                        File.WriteAllBytes(path, new byte[] { 0xff, 0xfe, 0x41, 0x00 });
                        Reject(delegate { ApprovedScript.Enroll("fixture", path, interpreter); }, "script_encoding_rejected");
                        File.WriteAllBytes(path, new byte[] { 0x23, 0x00, 0x41 });
                        Reject(delegate { ApprovedScript.Enroll("fixture", path, interpreter); }, "script_encoding_rejected");
                        File.WriteAllBytes(path, new byte[] { 239, 187, 191, 35, 32, 120 });
                        ApprovedScript bom = ApprovedScript.Enroll("fixture", path, interpreter);
                        using (PinnedScript pin = PinnedScript.Open(bom, false)) Assert(Marshal.ReadByte(pin.Code) == '#');
                        Reject(delegate { ApprovedScript.Enroll("fixture", path, @"C:\Tools\arbitrary.exe"); }, "script_policy_invalid");
                        ApprovedScript traversal = bom; traversal.FileName = @"..\fixture.ps1";
                        Reject(traversal.Validate, "script_policy_invalid");
                    });
                });
                Test("script nonzero exit is bounded failure and no code or raw stdout is serialized", delegate
                {
                    var runtime = new FakeRuntime { GuestProgramExit = 9 }; Grant(runtime, "TEST-VM", "runScriptInGuest");
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand("runScriptInGuest"), runtime));
                    Assert(!result.Ok && result.ErrorCode == "guest_program_failed" && result.Operation.GuestExit == 9);
                    string json = result.Json(); Assert(!json.Contains("fixture.ps1") && !json.Contains("powershell.exe") && !json.Contains("SYNTHETIC-CODE"));
                    Assert(Supervisor.Classify(result, 2, Stage.Complete, false, false, false).ExitCode == 2 && runtime.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("access reducing share commands require exact removal grants and cannot expose host paths", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "removeSharedFolder");
                    VmrunRequest command = VmrunRequest.Parse(new[] { "removeSharedFolder", "TEST-VM", "other-share" });
                    Reject(delegate { CatalogEngine.Execute(command, runtime); }, "share_not_approved");
                    Assert(!runtime.Events.Contains("connect") && !runtime.Events.Contains("official-cli:removeSharedFolder"));
                    VmrunRequest remove = SampleCommand("removeSharedFolder"); CliPlan plan = CliPlan.Build(remove, runtime.Resolve("TEST-VM"), null);
                    Assert(!plan.ReadOutput && String.Join(" ", plan.Arguments) == "-T ws removeSharedFolder " + runtime.Resolve("TEST-VM").Vmx + " synthetic");
                    Reject(delegate { RequestFor("vmrun", "removeSharedFolder", "TEST-VM", @"D:\host\folder"); }, "invalid_request");
                    foreach (string[] tokens in new[] { new[] { "disableSharedFolders", "TEST-VM" }, new[] { "disableSharedFolders", "TEST-VM", "runtime" } })
                    {
                        VmrunRequest disable = VmrunRequest.Parse(tokens); Grant(runtime = new FakeRuntime(), "TEST-VM", "disableSharedFolders");
                        CliPlan disablePlan = CliPlan.Build(disable, runtime.Resolve("TEST-VM"), null);
                        Assert(!disablePlan.ReadOutput && disablePlan.Arguments.Length == (tokens.Length == 2 ? 4 : 5));
                        Assert(ResultData.Parse(CatalogEngine.Execute(disable, runtime)).Operation.Completion == "cli_completed_not_verified");
                    }
                    foreach (string unavailable in new[] { "enableSharedFolders", "addSharedFolder", "setSharedFolderState" })
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(unavailable), new FakeRuntime()); }, "disposable_target_required");
                });
                Test("public scalar CLI accepts only canonical int32 or bool, never arbitrary strings", delegate
                {
                    foreach (string text in new[] { "0", "-1", "2147483647", "-2147483648", "true", "false" }) Assert(PublicScalar.Parse(text).Text == text);
                    foreach (string text in new[] { "", " 1", "+1", "01", "-0", "2147483648", "-2147483649", "1e3", "0x20", "TRUE", "secret", "1\n", "1.0" }) Reject(delegate { PublicScalar.Parse(text); }, "public_variable_value_rejected");
                    Reject(delegate { RequestFor("vmrun", "writeVariable", "TEST-VM", "guestVar", "PUBLIC_TEST", "SYNTHETIC-PRIVATE"); }, "public_variable_value_rejected");
                    Reject(delegate { RequestFor("vmrun", "writeVariable", "TEST-VM", "guestVar", "vmware_guest_broker.public.other", "1"); }, "invalid_request");
                });
                Test("public-variable policy fixes namespace, bounds and separate read/write rights", delegate
                {
                    PublicVariable progress = PublicVariable.PolicyLine("progress|int32|0|100|rw");
                    Assert(progress.NativeName == "vmware_guest_broker.public.progress" && progress.Read && progress.Write && progress.PolicyLine() == "progress|int32|0|100|rw");
                    progress.Check(PublicScalar.Parse("100")); Reject(delegate { progress.Check(PublicScalar.Parse("101")); }, "public_variable_value_rejected");
                    PublicVariable ready = PublicVariable.PolicyLine("ready|bool|r"); Assert(ready.Read && !ready.Write && ready.PolicyLine() == "ready|bool|r");
                    Reject(delegate { ready.Check(PublicScalar.Parse("1")); }, "public_variable_value_rejected");
                    foreach (string line in new[] { "key.name|bool|rw", "password/path|bool|r", "PASSWORD|int32|0|100|rw", "secretFlag|bool|r", "x|string|rw", "x|int32|9|1|rw", "x|bool|all", "x|bool|w|extra" })
                        Reject(delegate { PublicVariable.PolicyLine(line); }, "public_variable_policy_invalid");
                    Reject(delegate { progress.Check(new PublicScalar { Kind = "int32" }); }, "public_variable_value_rejected");
                });
                Test("public runtime read/write never retrieve credentials while legacy hostname still authenticates", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "writeVariable"); Grant(runtime, "TEST-VM", "readVariable");
                    ResultData write = ResultData.Parse(CatalogEngine.Execute(SampleCommand("writeVariable"), runtime));
                    Assert(write.Ok && write.Operation.IntegerValue == 3 && write.Operation.Authentication == "not_attempted");
                    VmrunRequest read = VmrunRequest.Parse(new[] { "readVariable", "TEST-VM", "guestVar", "PUBLIC_TEST" });
                    ResultData observation = ResultData.Parse(CatalogEngine.Execute(read, runtime));
                    Assert(observation.Operation.IntegerValue == 3 && observation.Operation.Variable == "PUBLIC_TEST" && !read.NeedsCredential);
                    Assert(!runtime.Events.Contains("vault") && !runtime.Events.Contains("prompt") && !runtime.Events.Contains("login") && runtime.Credential == null);
                    var legacy = new FakeRuntime(); Grant(legacy, "TEST-VM", "readVariable");
                    Assert(SampleCommand("readVariable").NeedsCredential);
                    Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand("readVariable"), legacy)).Operation.Computer == "SYNTHETIC-GUEST" && legacy.Events.Contains("login"));
                    VmrunRequest noCredentialFlag = VmrunRequest.Parse(new[] { "readVariable", "TEST-VM", "guestVar", "PUBLIC_TEST", "--stored" });
                    Assert(!noCredentialFlag.EnabledVariant);
                    Reject(delegate { CatalogEngine.Execute(noCredentialFlag, new FakeRuntime()); }, "catalog_operation_unavailable");
                });
                Test("public aliases cannot cross VM or bypass policy bounds write rights and revocation", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "SAFE-DC", "writeVariable");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("writeVariable"), runtime); }, "disposable_target_required");
                    Grant(runtime, "TEST-VM", "writeVariable"); CapabilityProfile profile = runtime.Policies[runtime.Resolve("TEST-VM").Binding];
                    profile.PublicVariables[0].Write = false;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("writeVariable"), runtime); }, "public_variable_not_granted");
                    profile.PublicVariables[0].Write = true;
                    VmrunRequest outOfRange = VmrunRequest.Parse(new[] { "writeVariable", "TEST-VM", "guestVar", "PUBLIC_TEST", "101" });
                    Reject(delegate { CatalogEngine.Execute(outOfRange, runtime); }, "public_variable_value_rejected");
                    runtime.Consent = false;
                    DenyGrant(runtime, "writeVariable"); Reject(delegate { CatalogEngine.Execute(SampleCommand("writeVariable"), runtime); }, "capability_not_granted");
                    Assert(!runtime.Events.Contains("operation:writeVariable") && runtime.Credential == null);
                    profile.Commands.Add("writeVariable"); runtime.RevokePolicyAtPrepare = true;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("writeVariable"), runtime); }, "capability_policy_changed");
                });
                Test("native scalar parser rejects arbitrary private data, overflow and noncanonical numeric strings", delegate
                {
                    PublicVariable number = PublicVariable.PolicyLine("counter|int32|-2147483648|2147483647|rw");
                    foreach (string text in new[] { "0", "-1", "2147483647", "-2147483648" })
                        using (SecretBuffer buffer = Vix.CopyNonSecretText(text)) Assert(PublicScalar.FromNative(buffer.Pointer, number).Text == text);
                    foreach (string text in new[] { "SYNTHETIC-PRIVATE", "12password", "2147483648", "999999999999999999999", "-2147483649", "01", "-0", "-", "", "+1", " 1" })
                        using (SecretBuffer buffer = Vix.CopyNonSecretText(text)) Reject(delegate { PublicScalar.FromNative(buffer.Pointer, number); }, "public_variable_value_rejected");
                    PublicVariable flag = PublicVariable.PolicyLine("ready|bool|rw");
                    using (SecretBuffer yes = Vix.CopyNonSecretText("true")) Assert(PublicScalar.FromNative(yes.Pointer, flag).Boolean == true);
                    using (SecretBuffer no = Vix.CopyNonSecretText("false")) Assert(PublicScalar.FromNative(no.Pointer, flag).Boolean == false);
                    using (SecretBuffer other = Vix.CopyNonSecretText("truePRIVATE")) Reject(delegate { PublicScalar.FromNative(other.Pointer, flag); }, "public_variable_value_rejected");
                });
                Test("generic environment/config writes and private reads stay gated before files or vault", delegate
                {
                    foreach (string[] raw in new[] { new[] { "writeVariable", "TEST-VM", "runtimeConfig", "isolation.tools.copy.disable", "false" }, new[] { "writeVariable", "TEST-VM", "guestEnv", "PASSWORD", "synthetic" }, new[] { "readVariable", "TEST-VM", "runtimeConfig", "RemoteDisplay.vnc.key" }, new[] { "readVariable", "TEST-VM", "guestEnv", "TOKEN" } })
                    {
                        var runtime = new FakeRuntime();
                        Reject(delegate { CatalogEngine.Execute(VmrunRequest.Parse(raw), runtime); }, "catalog_operation_unavailable");
                        Assert(runtime.Events.Count == 0 && runtime.Credential == null);
                    }
                    var missing = new FakeRuntime(); Grant(missing, "TEST-VM", "readVariable");
                    Reject(delegate { CatalogEngine.Execute(VmrunRequest.Parse(new[] { "readVariable", "TEST-VM", "guestVar", "unapproved" }), missing); }, "public_variable_not_granted");
                    Assert(!missing.Events.Contains("connect"));
                });
                Test("typed public results carry no arbitrary guest string and do not claim write readback", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "writeVariable");
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand("writeVariable"), runtime));
                    string json = result.Json(), human = Output.Human(result);
                    Assert(json.Contains("IntegerValue") && !json.Contains("NativeName") && !json.Contains("Password") && human.Contains("REQUEST ACK, not readback"));
                    result.Operation.BooleanValue = true;
                    Reject(result.Operation.Validate, "worker_protocol_failed");
                });
                Test("optional public-variable policy roundtrip preserves registry-v2 keys and old profiles", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target target = Synthetic("SAFE-DC", '1'); store.Add(target); CapabilityProfile old = CapabilityProfile.Default(target); store.WritePolicy(target, old);
                        Assert(store.ReadPolicy(target).PublicVariables == null);
                        old.PublicVariables = new List<PublicVariable> { PublicVariable.PolicyLine("progress|int32|0|100|rw") }; store.WritePolicy(target, old);
                        Assert(store.ReadPolicy(target).Variable("progress").Maximum == 100 && store.Read().Resolve(target.Name).CredentialKey == target.CredentialKey);
                        old.PublicVariables.Add(PublicVariable.PolicyLine("Progress|bool|r"));
                        Reject(delegate { old.Validate(target); }, "public_variable_policy_invalid");
                    });
                });
                Test("consent rendering normalizes LF CRLF and CR idempotently without changing content", delegate
                {
                    foreach (string value in new[] { "Command: a\nRisk: b\nVM: c", "Command: a\r\nRisk: b\r\nVM: c", "Command: a\rRisk: b\rVM: c" })
                    { string normalized = UiText.Lines(value); Assert(normalized == "Command: a\r\nRisk: b\r\nVM: c" && UiText.Lines(normalized) == normalized); }
                    Assert(UiText.Lines(null) == null && UiText.Lines("") == "" && UiText.Lines("public literal") == "public literal");
                });
                Test("helper fixture parser accepts only bounded relative public names, not absolute paths or key locations", delegate
                {
                    Assert(FixtureProtocol.Relative(@"sub\public.txt") == @"sub\public.txt");
                    foreach (string value in new[] { "", @"C:\outside.txt", @"\\host\x", @"..\outside.txt", @"a\..\b", @".ssh\id_rsa", "a/b", @"a.txt:stream", @"NUL.txt", @"COM1", @"file.", @"privatekey.txt", @"secret.key", @"x\token.txt" })
                        Reject(delegate { FixtureProtocol.Relative(value); }, "guest_fixture_path_rejected");
                    Reject(delegate { RequestFor("vmrun", "fileExistsInGuest", "TEST-VM", @"C:\BrokerTest\x"); }, "invalid_request");
                    Reject(delegate { RequestFor("vmrun", "fileExistsInGuest", "TEST-VM", "fixture", @"..\outside.txt"); }, "guest_fixture_path_rejected");
                });
                Test("guest helper core returns only file or directory existence inside exact enrolled handle-bound root", delegate
                {
                    WithGuestFixture(delegate (string root, GuestRootRecord record)
                    {
                        File.WriteAllText(Path.Combine(root, "public.txt"), "synthetic non-secret fixture"); Directory.CreateDirectory(Path.Combine(root, "sub"));
                        Assert(GuestProbe.Exists(record, "public.txt", false) && !GuestProbe.Exists(record, "public.txt", true));
                        Assert(GuestProbe.Exists(record, "sub", true) && !GuestProbe.Exists(record, "sub", false));
                        Assert(!GuestProbe.Exists(record, "absent.txt", false) && !GuestProbe.Exists(record, @"missing\absent.txt", false));
                        GuestRootRecord changed = GuestRootRecord.Capture(record.TargetBinding, "other", root, record.ImageSha256); changed.RootIdentity = new string('0', 64);
                        Reject(delegate { GuestProbe.Exists(changed, "public.txt", false); }, "guest_fixture_root_changed");
                        File.Delete(Path.Combine(root, "public.txt")); Directory.Delete(Path.Combine(root, "sub"));
                    });
                });
                Test("helper root receipts bind target generation and image, corrupt metadata cannot become false existence", delegate
                {
                    WithGuestFixture(delegate (string root, GuestRootRecord record)
                    {
                        var store = new GuestRootStore(Path.Combine(root, "store")); store.Save(record);
                        File.WriteAllText(Path.Combine(root, "public.txt"), "synthetic");
                        string[] request = { "probe-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "public.txt" };
                        Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.Exists);
                        request[5] = "absent.txt"; Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.Missing);
                        request[3] = new string('C', 32); Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.NotEnrolled);
                        request[3] = record.EnrollmentId; request[4] = new string('C', 64); Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.ImageChanged);
                        request[4] = record.ImageSha256;
                        string policy = Path.Combine(root, "store", record.TargetBinding + "-" + record.Alias + ".json"); File.WriteAllText(policy, "{} trailing");
                        int refused = GuestProbe.Request(store, record.ImageSha256, request); Assert(refused != FixtureProtocol.Exists && refused != FixtureProtocol.Missing);
                        File.Delete(Path.Combine(root, "public.txt")); foreach (string file in Directory.GetFiles(Path.Combine(root, "store"))) File.Delete(file); Directory.Delete(Path.Combine(root, "store"));
                    });
                });
                Test("real synthetic guest-root junction and hardlink aliases are rejected without reading contents", delegate
                {
                    WithGuestFixture(delegate (string root, GuestRootRecord record)
                    {
                        string outside = root + "-outside"; Directory.CreateDirectory(outside); File.WriteAllText(Path.Combine(outside, "public.txt"), "synthetic");
                        string link = Path.Combine(root, "link"), hard = Path.Combine(root, "alias.txt");
                        try
                        {
                            MakeFixtureLink("/J", link, outside); MakeFixtureLink("/H", hard, Path.Combine(outside, "public.txt"));
                            Reject(delegate { GuestProbe.Exists(record, @"link\public.txt", false); }, "export_path_redirected");
                            Reject(delegate { GuestProbe.Exists(record, "alias.txt", false); }, "export_path_redirected");
                        }
                        finally { if (File.Exists(hard)) File.Delete(hard); if (Directory.Exists(link)) Directory.Delete(link); File.Delete(Path.Combine(outside, "public.txt")); Directory.Delete(outside); }
                    });
                });
                Test("helper-backed broker queries require exact receipt and command grant before credentials, no approval UI", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "fileExistsInGuest"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures.Clear();
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("fileExistsInGuest"), runtime); }, "guest_fixture_not_approved");
                    Assert(!runtime.Events.Contains("connect") && runtime.Credential == null);
                    runtime = new FakeRuntime { Consent = false }; Grant(runtime, "TEST-VM", "fileExistsInGuest");
                    DenyGrant(runtime, "fileExistsInGuest"); Reject(delegate { CatalogEngine.Execute(SampleCommand("fileExistsInGuest"), runtime); }, "capability_not_granted");
                    Assert(!runtime.Events.Contains("vault") && !runtime.Events.Contains("login"));
                    var yes = new FakeRuntime(); Grant(yes, "TEST-VM", "fileExistsInGuest");
                    ResultData report = ResultData.Parse(CatalogEngine.Execute(SampleCommand("fileExistsInGuest"), yes));
                    Assert(report.Operation.Exists == true && report.Operation.Fixture == "fixture" && report.Operation.Backend == "native-vix-helper" && report.Operation.GuestExit == null);
                    Assert(!report.Json().Contains("public.txt") && !report.Json().Contains("BrokerTools") && !report.Json().Contains("EnrollmentId"));
                });
                Test("compiled helper image and metadata-only native carrier plan agree, no copy or install endpoint", delegate
                {
                    string image = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "broker-guest-helper.exe");
                    Assert(FixtureProtocol.ImageHash(image) == HelperBuild.Hash);
                    var profile = CapabilityProfile.Default(Synthetic("TEST-VM", '2'));
                    var fixture = new GuestFixture { Alias = "fixture", EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = HelperBuild.Hash };
                    fixture.Validate(); string arguments = fixture.Arguments(Synthetic("TEST-VM", '2'), SampleCommand("fileExistsInGuest"));
                    Assert(arguments.Contains("probe-file") && arguments.Contains(HelperBuild.Hash) && !arguments.Contains("password"));
                    fixture.ImageSha256 = new string('0', 64); Reject(delegate { fixture.DemandImage(SampleCommand("fileExistsInGuest")); }, "guest_fixture_image_unavailable");
                    Assert(profile.GuestFixtures == null && !profile.Disposable);
                });
                Test("owned fixture native ABI creates empty private objects relative to pinned parent handles", delegate
                {
                    Assert(Marshal.SizeOf(typeof(Native.UnicodeName)) == 8 && Marshal.SizeOf(typeof(Native.ObjectAttributes)) == 24 && Marshal.SizeOf(typeof(Native.IoStatus)) == 8);
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "empty.txt");
                        GuestOwned.Apply(store, record, "create-directory", "emptydir");
                        Assert(new FileInfo(Path.Combine(root, "empty.txt")).Length == 0 && Directory.Exists(Path.Combine(root, "emptydir")));
                        HostPaths.CheckPrivateFile(Path.Combine(root, "empty.txt")); HostPaths.CheckPrivateDirectory(Path.Combine(root, "emptydir"));
                        Assert(store.ReadOwned(record).Items.Count == 2);
                        GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\nested.txt");
                        Assert(File.Exists(Path.Combine(root, "emptydir", "nested.txt")) && store.ReadOwned(record).Items.Count == 3);
                    });
                });
                Test("owned fixture creation refuses existing names of either kind and missing parents without overwriting data", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(root, "foreign.txt"), "synthetic public data must remain");
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "foreign.txt"); }, "guest_fixture_create_refused");
                        Reject(delegate { GuestOwned.Apply(store, record, "create-directory", "foreign.txt"); }, "guest_fixture_create_refused");
                        GuestOwned.Apply(store, record, "create-directory", "owned-dir");
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "owned-dir"); }, "guest_fixture_create_refused");
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", @"missing\new.txt"); }, "export_root_unavailable");
                        Assert(File.ReadAllText(Path.Combine(root, "foreign.txt")) == "synthetic public data must remain" && !Directory.Exists(Path.Combine(root, "missing")));
                    });
                });
                Test("owned fixture deletion and legacy arbitrary rename grammar stay gated even with an owned empty file", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt");
                        foreach (string operation in new[] { "delete-file", "delete-directory", "rename-file" })
                        {
                            Reject(delegate { GuestOwned.Apply(store, record, operation, "old.txt"); }, "guest_fixture_owned_refused");
                            Assert(GuestProbe.Request(store, record.ImageSha256, new[] { operation, record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "old.txt" }) == FixtureProtocol.Invalid);
                        }
                        Assert(File.Exists(Path.Combine(root, "old.txt")));
                    });
                });
                Test("owned fixture creation requires both opt-ins and current root generation", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        record.OwnedMutations = false; store.Save(record);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "owned.txt"); }, "guest_fixture_owned_refused");
                        record.OwnedMutations = true; store.Save(record); GuestOwned.Apply(store, record, "create-empty-file", "owned.txt");
                        GuestRootRecord revoked = GuestRootRecord.Capture(record.TargetBinding, record.Alias, root, record.ImageSha256); store.Save(revoked);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "another.txt"); }, "guest_fixture_owned_refused");
                    });
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "CreateTempfileInGuest"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures[0].OwnedMutations = false;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("CreateTempfileInGuest"), runtime); }, "guest_fixture_owned_refused");
                    Assert(runtime.Credential == null && !runtime.Events.Contains("connect"));
                });
                Test("metadata publication failure never becomes mutation success or an arbitrary delete grant", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        Action failure = delegate { throw new IOException("synthetic publication failure"); };
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "new.txt", failure); }, "guest_fixture_mutation_uncertain");
                        Assert(File.Exists(Path.Combine(root, "new.txt")) && store.ReadOwned(record).Items.Count == 0);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "new.txt"); }, "guest_fixture_create_refused");
                        Reject(delegate { GuestOwned.Apply(store, record, "create-directory", "emptydir", failure); }, "guest_fixture_mutation_uncertain");
                        Assert(Directory.Exists(Path.Combine(root, "emptydir")) && store.ReadOwned(record).Items.Count == 0);
                    });
                });
                Test("creation retains data-read parent pins against rename until the native request is complete", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir");
                        using (FixtureParent parent = FixtureParent.Open(record, @"emptydir\pinned.txt"))
                        {
                            bool refused = false;
                            try { Directory.Move(Path.Combine(root, "emptydir"), Path.Combine(root, "dest")); } catch (IOException) { refused = true; }
                            Assert(refused);
                            using (var handle = OwnedNative.Create(parent.Handle, parent.Leaf, false)) HostPaths.CheckHandle(handle, Path.Combine(root, "emptydir", "pinned.txt"), false);
                        }
                    });
                });
                Test("creation rejects real synthetic junction ancestry and hardlink leaf names without outside writes", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        string outside = Path.Combine(root, "dest"), link = Path.Combine(root, "redirect"), hard = Path.Combine(root, "linked.txt");
                        Directory.CreateDirectory(outside); File.WriteAllText(Path.Combine(outside, "public.txt"), "synthetic preserved");
                        MakeFixtureLink("/J", link, outside); MakeFixtureLink("/H", hard, Path.Combine(outside, "public.txt"));
                        try
                        {
                            Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", @"redirect\new.txt"); }, "export_path_redirected");
                            Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "linked.txt"); }, "guest_fixture_create_refused");
                            Reject(delegate { GuestOwned.Apply(store, record, "create-directory", "redirect"); }, "guest_fixture_create_refused");
                            Assert(!File.Exists(Path.Combine(outside, "new.txt")) && File.ReadAllText(Path.Combine(outside, "public.txt")) == "synthetic preserved");
                        }
                        finally { File.Delete(hard); Directory.Delete(link); }
                    });
                });
                Test("creation root identity old protocol and stale public receipts refuse before object creation", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        string id = record.RootIdentity; record.RootIdentity = new string('0', 64);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "bad.txt"); }, "guest_fixture_root_changed"); record.RootIdentity = id;
                        record.Version = 1; Reject(record.Validate, "guest_fixture_policy_invalid"); record.Version = FixtureProtocol.Version;
                        Assert(GuestProbe.Request(store, record.ImageSha256, new[] { "create-empty-file", record.TargetBinding, record.Alias, new string('0', 32), record.ImageSha256, "bad.txt" }) == FixtureProtocol.NotEnrolled);
                        Assert(GuestProbe.Request(store, record.ImageSha256, new[] { "create-empty-file", record.TargetBinding, record.Alias, record.EnrollmentId, new string('0', 64), "bad.txt" }) == FixtureProtocol.ImageChanged);
                        Assert(!File.Exists(Path.Combine(root, "bad.txt")));
                    });
                });
                Test("creation ledger cap and corrupt metadata never authorize another object", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        var ledger = new OwnedLedger { EnrollmentId = record.EnrollmentId };
                        for (int i = 0; i < 64; i++) ledger.Items.Add(new OwnedFixture { Relative = "item" + i + ".txt", Identity = new string('A', 64) });
                        store.WriteOwned(record, ledger);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "overflow.txt"); }, "guest_fixture_create_refused");
                        string path = Path.Combine(root, "store", "owned-" + record.TargetBinding + "-" + record.Alias + "-" + record.EnrollmentId + ".json");
                        foreach (string invalid in new[] { "null", "{}", "{broken", new string('x', 32769) })
                        {
                            File.WriteAllText(path, invalid);
                            int code = GuestProbe.Request(store, record.ImageSha256, new[] { "create-empty-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "overflow.txt" });
                            Assert(code != 0 && code != FixtureProtocol.MutationUncertain && !File.Exists(Path.Combine(root, "overflow.txt")));
                        }
                    });
                });
                Test("creation missing grant and policy revocation stop before credentials or helper dispatch", delegate
                {
                    foreach (string name in new[] { "createDirectoryInGuest", "CreateTempfileInGuest" })
                    {
                        var cancel = new FakeRuntime { Consent = false }; Grant(cancel, "TEST-VM", name);
                        DenyGrant(cancel, name); Reject(delegate { CatalogEngine.Execute(SampleCommand(name), cancel); }, "capability_not_granted");
                        Assert(cancel.Credential == null && !cancel.Events.Contains("prepare-private-inputs") && !cancel.Events.Contains("operation:" + name));
                        var revoked = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(revoked, "TEST-VM", name);
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), revoked); }, "capability_policy_changed"); Assert(revoked.Credential == null);
                    }
                });
                Test("optional host creation opt-in is fingerprinted and roundtrips without changing registry-v2 credential keys", delegate
                {
                    WithRegistry(delegate (string path, RegistryStore store)
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "CreateTempfileInGuest"); Target target = runtime.Resolve("TEST-VM");
                        store.Add(target);
                        CapabilityProfile policy = runtime.Policies[target.Binding]; string key = target.CredentialKey, fingerprint = policy.Fingerprint();
                        store.WritePolicy(target, policy); Assert(store.ReadPolicy(target).GuestFixtures[0].OwnedMutations);
                        policy.GuestFixtures[0].OwnedMutations = false; Assert(policy.Fingerprint() != fingerprint);
                        store.WritePolicy(target, policy); Assert(!store.ReadPolicy(target).GuestFixtures[0].OwnedMutations && target.CredentialKey == key);
                    });
                });
                Test("creation ACK is typed not an existence result and unrecognized or I/O statuses mean unknown outcome", delegate
                {
                    VmrunRequest request = SampleCommand("CreateTempfileInGuest"); OperationReport report = OperationReport.New(request);
                    foreach (long status in new long[] { 1, FixtureProtocol.IoFailure, FixtureProtocol.MutationUncertain, -1, 0xC0000005 })
                        Reject(delegate { GuestFixture.Complete(report, "fixture", status); }, "guest_fixture_mutation_uncertain");
                    foreach (long status in new long[] { FixtureProtocol.Invalid, FixtureProtocol.RootChanged, FixtureProtocol.Redirected, FixtureProtocol.NotEnrolled, FixtureProtocol.ImageChanged, FixtureProtocol.MutationRefused })
                        Reject(delegate { GuestFixture.Complete(report, "fixture", status); }, "guest_fixture_helper_refused");
                    GuestFixture.Complete(report, "fixture", 0); report.Validate();
                    string json = new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json();
                    Assert(ResultData.Parse(json).Operation.FixtureAction == "create-empty-file" && !json.Contains("public.txt") && !report.Exists.HasValue);
                    report.Exists = true; Reject(report.Validate, "worker_protocol_failed"); report.Exists = null;
                    report.FixtureAction = "delete-file"; Reject(report.Validate, "worker_protocol_failed");
                });
                Test("current protocol creation uses actual helper core and refuses a later existing name without replacing it", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        string[] argsForFile = { "create-empty-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "created.txt" };
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForFile) == 0 && File.Exists(Path.Combine(root, "created.txt")));
                        File.WriteAllText(Path.Combine(root, "created.txt"), "synthetic preserved after creation");
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForFile) == FixtureProtocol.MutationRefused && File.ReadAllText(Path.Combine(root, "created.txt")) == "synthetic preserved after creation");
                        Assert(GuestProbe.Request(store, record.ImageSha256, new[] { "create-directory", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir" }) == 0);
                        record.OwnedMutations = false; store.Save(record); argsForFile[5] = "denied.txt";
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForFile) == FixtureProtocol.MutationRefused && !File.Exists(Path.Combine(root, "denied.txt")));
                    });
                });
                Test("guest root enrollment and object creation share one non-reentrant writer lease", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        using (store.MutationLock())
                        {
                            bool denied = false;
                            try { store.Save(record); } catch (IOException) { denied = true; }
                            Assert(denied);
                            Assert(GuestProbe.Request(store, record.ImageSha256, new[] { "create-empty-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "locked.txt" }) != 0 && !File.Exists(Path.Combine(root, "locked.txt")));
                        }
                        GuestOwned.Apply(store, record, "create-empty-file", "locked.txt"); Assert(File.Exists(Path.Combine(root, "locked.txt")));
                    });
                });
                Test("native handle directory enumeration counts immediate public files and directories without recursion", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "a.txt"), "synthetic public data"); File.WriteAllText(Path.Combine(path, "b.txt"), "");
                        string subdir = Path.Combine(path, "subdir"); Directory.CreateDirectory(subdir); File.WriteAllText(Path.Combine(subdir, "synthetic.key"), "synthetic NOT a key");
                        try { ListingCounts counts = GuestListing.Observe(record, "emptydir"); Assert(counts.Files == 2 && counts.Directories == 1); }
                        finally { File.Delete(Path.Combine(subdir, "synthetic.key")); Directory.Delete(subdir); }
                        Assert(File.ReadAllText(Path.Combine(path, "a.txt")) == "synthetic public data");
                    });
                });
                Test("empty listing is a reserved encoded observation not boolean zero or a missing directory", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        ListingCounts counts = GuestListing.Observe(record, "emptydir"); Assert(counts.Files == 0 && counts.Directories == 0 && counts.Encode() == ListingCounts.Base);
                        Reject(delegate { GuestListing.Observe(record, "missing"); }, "export_root_unavailable");
                        File.WriteAllText(Path.Combine(record.RootPath, "regular.txt"), "");
                        Reject(delegate { GuestListing.Observe(record, "regular.txt"); }, "export_path_redirected");
                    });
                });
                Test("native listing accepts64 entries but refuses65 without a truncated successful result", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        for (int i = 0; i < 64; i++) File.WriteAllText(Path.Combine(path, "item" + i + ".txt"), "");
                        Assert(GuestListing.Observe(record, "emptydir").Files == 64);
                        File.WriteAllText(Path.Combine(path, "overflow.txt"), "");
                        Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused");
                    });
                });
                Test("native listing refuses real synthetic junction and hardlink entries without following or reading them", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string outside = Path.Combine(record.RootPath, "outside.txt"), link = Path.Combine(path, "redirect"), hard = Path.Combine(path, "linked.txt");
                        File.WriteAllText(outside, "synthetic outside"); MakeFixtureLink("/J", link, record.RootPath);
                        try { Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused"); } finally { Directory.Delete(link); }
                        MakeFixtureLink("/H", hard, outside);
                        try { Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "export_path_redirected"); } finally { File.Delete(hard); }
                        Assert(File.ReadAllText(outside) == "synthetic outside");
                    });
                });
                Test("listing refuses secret-shaped names hidden entries and unsafe names with no output", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string key = Path.Combine(path, "synthetic.key"); File.WriteAllText(key, "synthetic NOT a key");
                        Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_path_rejected"); File.Delete(key);
                        string hidden = Path.Combine(path, "hidden.txt"); File.WriteAllText(hidden, ""); File.SetAttributes(hidden, FileAttributes.Hidden);
                        try { Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused"); } finally { File.SetAttributes(hidden, FileAttributes.Normal); }
                    });
                });
                Test("listing rejects locked entries instead of returning a partial count or false empty", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string file = Path.Combine(path, "locked.txt");
                        using (var writer = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                            Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused");
                        Assert(GuestListing.Observe(record, "emptydir").Files == 1);
                    });
                });
                Test("listing requires a separate guest opt-in, not new-empty creation authority", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string[] argsForList = { "list-counts", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir" };
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForList) == ListingCounts.Base);
                        record.PublicListing = false; record.OwnedMutations = true; store.Save(record);
                        Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused");
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForList) < ListingCounts.Base);
                        record.PublicListing = true; record.OwnedMutations = false; store.Save(record);
                        Assert(GuestProbe.Request(store, record.ImageSha256, argsForList) == ListingCounts.Base);
                    });
                });
                Test("listing receipt binds root target image generation and rejects frozen protocol2 records", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string id = record.RootIdentity; record.RootIdentity = new string('0', 64);
                        Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_root_changed"); record.RootIdentity = id;
                        record.Version = 2; Reject(record.Validate, "guest_fixture_policy_invalid"); record.Version = FixtureProtocol.Version;
                        foreach (int field in new[] { 1, 3, 4 })
                        {
                            string[] argsForList = { "list-counts", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir" };
                            argsForList[field] = new string('0', field == 3 ? 32 : 64);
                            Assert(GuestProbe.Request(store, record.ImageSha256, argsForList) < ListingCounts.Base);
                        }
                    });
                });
                Test("listing host opt-in exact grants and revocation stop before credentials or guest dispatch", delegate
                {
                    var missing = new FakeRuntime(); Grant(missing, "TEST-VM", "listDirectoryInGuest"); missing.Policies[missing.Resolve("TEST-VM").Binding].GuestFixtures[0].PublicListing = false;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("listDirectoryInGuest"), missing); }, "guest_fixture_listing_refused"); Assert(!missing.Events.Contains("connect"));
                    var cancel = new FakeRuntime { Consent = false }; Grant(cancel, "TEST-VM", "listDirectoryInGuest");
                    DenyGrant(cancel, "listDirectoryInGuest"); Reject(delegate { CatalogEngine.Execute(SampleCommand("listDirectoryInGuest"), cancel); }, "capability_not_granted"); Assert(cancel.Credential == null && !cancel.Events.Contains("prepare-private-inputs"));
                    var revoke = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(revoke, "TEST-VM", "listDirectoryInGuest");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("listDirectoryInGuest"), revoke); }, "capability_policy_changed"); Assert(revoke.Credential == null);
                });
                Test("listing receipt flags parse exactly, remain independent and participate in policy fingerprints", delegate
                {
                    string prefix = "fixture|" + new string('A', 32) + @"|C:\BrokerTools\broker-guest-helper.exe";
                    foreach (string suffix in new[] { "", "|owned-empty", "|public-counts", "|owned-empty,public-counts" })
                    {
                        GuestFixture fixture = GuestFixture.PolicyLine(prefix + suffix); fixture.Validate(); Assert(fixture.PolicyLine() == prefix + suffix);
                        Assert(fixture.PublicListing == suffix.Contains("public-counts") && fixture.OwnedMutations == suffix.Contains("owned-empty"));
                    }
                    foreach (string suffix in new[] { "|", "|all", "|public-counts,owned-empty", "|public-counts,public-counts", "|public-counts|owned-empty" })
                        Reject(delegate { GuestFixture.PolicyLine(prefix + suffix); }, "guest_fixture_policy_invalid");
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "listDirectoryInGuest"); CapabilityProfile profile = runtime.Policies[runtime.Resolve("TEST-VM").Binding];
                    string fingerprint = profile.Fingerprint(); profile.GuestFixtures[0].PublicListing = false; Assert(profile.Fingerprint() != fingerprint);
                });
                Test("directory-count encoding exhaustively roundtrips valid pairs and rejects holes and all legacy statuses", delegate
                {
                    for (int f = 0; f <= 64; f++) for (int d = 0; d <= 64; d++)
                    {
                        long code = ListingCounts.Base + f * 65 + d;
                        if (f + d > 64) Reject(delegate { ListingCounts.Decode(code); }, "guest_fixture_listing_refused");
                        else { ListingCounts c = ListingCounts.Decode(code); Assert(c.Files == f && c.Directories == d && c.Encode() == code); }
                    }
                    foreach (long code in new long[] { -1, 0, 1, 20, 21, 22, 23, 24, 25, 26, 27, ListingCounts.Base - 1, ListingCounts.Base + 65 * 65, 0xC0000005, Int64.MaxValue })
                        Reject(delegate { ListingCounts.Decode(code); }, "guest_fixture_listing_refused");
                });
                Test("directory buffer parser handles aligned records and skips dot entries without exporting raw names", delegate
                {
                    WithListingBuffer(delegate (IntPtr buffer)
                    {
                        int offset = 0; offset += DirectoryRecord(buffer, offset, ".", 0x10, true); offset += DirectoryRecord(buffer, offset, "..", 0x10, true);
                        offset += DirectoryRecord(buffer, offset, "public.txt", 0x20, true); DirectoryRecord(buffer, offset, "subdir", 0x10, false);
                        int files = 0, directories = 0;
                        GuestListing.ParseBatch(buffer, GuestListing.BufferBytes, delegate (string name, bool dir) { if (dir) directories++; else files++; });
                        Assert(files == 1 && directories == 1);
                    });
                });
                Test("directory buffer parser rejects invalid offsets lengths traversal names and reparse flags", delegate
                {
                    foreach (Action<IntPtr> corrupt in new Action<IntPtr>[] {
                        delegate(IntPtr p) { Marshal.WriteInt32(p, 7); }, delegate(IntPtr p) { Marshal.WriteInt32(p, Int32.MaxValue); },
                        delegate(IntPtr p) { Marshal.WriteInt32(p, 60, 1); }, delegate(IntPtr p) { Marshal.WriteInt32(p, 60, 98); },
                        delegate(IntPtr p) { Marshal.WriteInt32(p, 60, -2); }, delegate(IntPtr p) { Marshal.WriteInt32(p, 56, 0x400); },
                        delegate(IntPtr p) { Marshal.WriteInt32(p, 56, 0); }, delegate(IntPtr p) { Marshal.WriteInt32(p, 56, Int32.MinValue); } })
                        WithListingBuffer(delegate (IntPtr buffer) { DirectoryRecord(buffer, 0, "public.txt", 0x20, false); corrupt(buffer); Reject(delegate { GuestListing.ParseBatch(buffer, GuestListing.BufferBytes, delegate { throw new Exception("must not emit"); }); }, "guest_fixture_listing_refused"); });
                    foreach (string name in new[] { @"a\b", "../x", "a:b", "a\0b", "Ω.txt", "synthetic.key" })
                        WithListingBuffer(delegate (IntPtr buffer) { DirectoryRecord(buffer, 0, name, 0x20, false); Reject(delegate { GuestListing.ParseBatch(buffer, GuestListing.BufferBytes, delegate { throw new Exception("must not emit"); }); }, "guest_fixture_path_rejected"); });
                });
                Test("directory counts serialize only typed alias and counts, never relative names or existence success", delegate
                {
                    OperationReport report = OperationReport.New(SampleCommand("listDirectoryInGuest")); GuestFixture.Complete(report, "fixture", new ListingCounts(2, 1).Encode()); report.Validate();
                    string json = new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json(); ResultData roundtrip = ResultData.Parse(json);
                    Assert(roundtrip.Operation.FixtureFiles == 2 && roundtrip.Operation.FixtureDirectories == 1 && !json.Contains("public.txt") && !json.Contains("RootPath") && !report.Exists.HasValue);
                    string human = Output.Human(roundtrip); Assert(human.IndexOf("counts", StringComparison.OrdinalIgnoreCase) >= 0 && human.Contains("NOT a snapshot"));
                    report.Count = 4; Reject(report.Validate, "worker_protocol_failed"); report.Count = 3;
                    report.Exists = true; Reject(report.Validate, "worker_protocol_failed"); report.Exists = null;
                    report.FixtureFiles = -1; Reject(report.Validate, "worker_protocol_failed"); report.FixtureFiles = 2;
                    report.FixtureDirectories = null; Reject(report.Validate, "worker_protocol_failed"); report.FixtureDirectories = 1;
                    report.FixtureFiles = Int32.MaxValue; report.FixtureDirectories = Int32.MaxValue; Reject(report.Validate, "worker_protocol_failed"); report.FixtureFiles = 2; report.FixtureDirectories = 1;
                    report.Command = "fileExistsInGuest"; Reject(report.Validate, "worker_protocol_failed");
                });
                Test("listing public opt-in roundtrips privately with absent flags default false and unchanged v2 credential keys", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "listDirectoryInGuest"); Target target = runtime.Resolve("TEST-VM"); store.Add(target);
                        string key = target.CredentialKey; CapabilityProfile policy = runtime.Policies[target.Binding];
                        store.WritePolicy(target, policy); Assert(store.ReadPolicy(target).GuestFixtures[0].PublicListing);
                        policy.GuestFixtures[0].PublicListing = false; store.WritePolicy(target, policy); Assert(!store.ReadPolicy(target).GuestFixtures[0].PublicListing && target.CredentialKey == key);
                    });
                });
                Test("bounded NT same-parent basename rename feasibility retains all parent pins and never replaces an existing name", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "rename-old.txt");
                        using (FixtureParent parent = FixtureParent.Open(record, "rename-old.txt"))
                        {
                            var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                            using (var file = Native.CreateFileW(Path.Combine(root, parent.Leaf), 0x10081, 1, ref security, 3, 0x02000000 | 0x00200000, IntPtr.Zero))
                            {
                                Assert(!file.IsInvalid); HostPaths.CheckHandle(file, Path.Combine(root, parent.Leaf), false);
                                bool replacementDenied = false;
                                try { File.Move(Path.Combine(root, parent.Leaf), Path.Combine(root, "external-move.txt")); } catch (IOException) { replacementDenied = true; }
                                Assert(replacementDenied && File.Exists(Path.Combine(root, parent.Leaf)));
                                OwnedNative.RenameSameParent(file, "rename-new.txt"); HostPaths.CheckHandle(file, Path.Combine(root, "rename-new.txt"), false);
                            }
                        }
                        Assert(File.Exists(Path.Combine(root, "rename-new.txt")) && !File.Exists(Path.Combine(root, "rename-old.txt")));
                    });
                });
                Test("owned-file rename updates exact identity within the same nested parent and retains creation accounting", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\old.txt");
                        OwnedLedger before = store.ReadOwned(record); string id = before.Items[1].Identity;
                        GuestRename.Apply(store, record, @"emptydir\old.txt", "new.txt"); OwnedLedger after = store.ReadOwned(record);
                        Assert(after.Items.Count == before.Items.Count && after.Items[1].Identity == id && after.Items[1].Relative == @"emptydir\new.txt");
                        Assert(!File.Exists(Path.Combine(root, "emptydir", "old.txt")) && File.Exists(Path.Combine(root, "emptydir", "new.txt")));
                        GuestRename.Apply(store, record, @"emptydir\new.txt", "again.txt"); Assert(store.ReadOwned(record).Items[1].Identity == id);
                    });
                });
                Test("kernel no-replacement rename refuses existing foreign file and directory without changing either object", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); File.WriteAllText(Path.Combine(root, "existing.txt"), "synthetic preserved"); Directory.CreateDirectory(Path.Combine(root, "emptydir"));
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "existing.txt"); }, "guest_fixture_rename_refused");
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "emptydir"); }, "guest_fixture_rename_refused");
                        Assert(File.Exists(Path.Combine(root, "old.txt")) && File.ReadAllText(Path.Combine(root, "existing.txt")) == "synthetic preserved" && Directory.Exists(Path.Combine(root, "emptydir")) && store.ReadOwned(record).Items[0].Relative == "old.txt");
                    });
                });
                Test("rename refuses foreign files owned directories and ledger-reserved destination names before native mutation", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(root, "foreign.txt"), "");
                        Reject(delegate { GuestRename.Apply(store, record, "foreign.txt", "new.txt"); }, "guest_fixture_owned_refused");
                        GuestOwned.Apply(store, record, "create-directory", "emptydir");
                        Reject(delegate { GuestRename.Apply(store, record, "emptydir", "other"); }, "guest_fixture_owned_refused");
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); GuestOwned.Apply(store, record, "create-empty-file", "reserved.txt"); File.Delete(Path.Combine(root, "reserved.txt"));
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "reserved.txt"); }, "guest_fixture_owned_refused"); Assert(File.Exists(Path.Combine(root, "old.txt")));
                    });
                });
                Test("rename refuses nonzero primary stream and same-name file replacement rather than borrowing stale ownership", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); File.WriteAllText(Path.Combine(root, "old.txt"), "synthetic changed");
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "guest_fixture_not_empty");
                        File.WriteAllText(Path.Combine(root, "replacement.txt"), ""); File.Replace(Path.Combine(root, "replacement.txt"), Path.Combine(root, "old.txt"), null);
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "guest_fixture_owned_refused"); Assert(!File.Exists(Path.Combine(root, "new.txt")));
                    });
                });
                Test("rename rechecks private ACL instead of treating recorded ownership as permanent permission", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); string path = Path.Combine(root, "old.txt");
                        var security = File.GetAccessControl(path); security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null), System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow)); File.SetAccessControl(path, security);
                        try { Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "export_acl_rejected"); }
                        finally { File.SetAccessControl(path, HostPaths.FileSecurity()); }
                        Assert(File.Exists(path) && !File.Exists(Path.Combine(root, "new.txt")));
                    });
                });
                Test("same-parent rename preserves known synthetic named stream bytes without claiming all-stream emptiness", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); byte[] expected = { 1, 7, 4, 2 };
                        var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                        using (var handle = Native.CreateFileW(Path.Combine(root, "old.txt") + ":public-fixture", 0x40000000, 1, ref security, 1, 0, IntPtr.Zero))
                        using (var stream = new FileStream(handle, FileAccess.Write)) stream.Write(expected, 0, expected.Length);
                        GuestRename.Apply(store, record, "old.txt", "new.txt");
                        using (var handle = Native.CreateFileW(Path.Combine(root, "new.txt") + ":public-fixture", 0x80000000, 1, ref security, 3, 0, IntPtr.Zero))
                        using (var stream = new FileStream(handle, FileAccess.Read))
                        { byte[] actual = new byte[4]; Assert(stream.Read(actual, 0, actual.Length) == 4 && BitConverter.ToString(actual) == BitConverter.ToString(expected)); }
                        Assert(new FileInfo(Path.Combine(root, "new.txt")).Length == 0);
                    });
                });
                Test("rename requires distinct guest opt-in and rejects old protocol3 enrollment without migration", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); record.OwnedRenames = false; record.PublicListing = true; store.Save(record);
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "guest_fixture_owned_refused");
                        record.Version = 3; Reject(record.Validate, "guest_fixture_policy_invalid"); record.Version = FixtureProtocol.Version;
                        record.OwnedRenames = true; record.OwnedMutations = false; store.Save(record); GuestRename.Apply(store, record, "old.txt", "new.txt"); Assert(File.Exists(Path.Combine(root, "new.txt")));
                    });
                });
                Test("post-rename ledger failure is unknown and cannot authorize either moved path or a recreated old name", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt");
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt", delegate { throw new IOException("synthetic publication failure"); }); }, "guest_fixture_mutation_uncertain");
                        Assert(!File.Exists(Path.Combine(root, "old.txt")) && File.Exists(Path.Combine(root, "new.txt")) && store.ReadOwned(record).Items[0].Relative == "old.txt");
                        Reject(delegate { GuestRename.Apply(store, record, "new.txt", "again.txt"); }, "guest_fixture_owned_refused");
                        using (FixtureParent replacement = FixtureParent.Open(record, "old.txt"))
                        using (var file = OwnedNative.Create(replacement.Handle, replacement.Leaf, false)) HostPaths.CheckHandle(file, Path.Combine(root, "old.txt"), false);
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "again.txt"); }, "guest_fixture_owned_refused"); Assert(!File.Exists(Path.Combine(root, "again.txt")));
                    });
                });
                Test("protocol4 rename accepts exact seven-field request and returns ACK only for the actual owned operation", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt");
                        string[] request = { "rename-owned-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "old.txt", "new.txt" };
                        Assert(GuestProbe.Request(store, record.ImageSha256, request) == 0 && File.Exists(Path.Combine(root, "new.txt")));
                        Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.MutationRefused);
                        request[6] = @"elsewhere\new.txt"; Assert(GuestProbe.Request(store, record.ImageSha256, request) == FixtureProtocol.Invalid);
                    });
                });
                Test("rename CLI refuses paths traversal secrets case-only and legacy absolute forms before any runtime", delegate
                {
                    foreach (string destination in new[] { @"elsewhere\new.txt", @"C:\new.txt", "../new.txt", "new.txt:stream", "synthetic.key" })
                        Reject(delegate { VmrunRequest.Parse(new[] { "renameFileInGuest", "TEST-VM", "fixture", "old.txt", destination, "--stored" }); }, "guest_fixture_path_rejected");
                    Reject(delegate { VmrunRequest.Parse(new[] { "renameFileInGuest", "TEST-VM", "fixture", "old.txt", "OLD.TXT" }); }, "guest_fixture_rename_refused");
                    Reject(delegate { VmrunRequest.Parse(new[] { "renameFileInGuest", "TEST-VM", @"C:\old.txt", @"C:\new.txt" }); }, "invalid_request");
                });
                Test("rename flags roundtrip all independent combinations and reject duplicated or reordered rights", delegate
                {
                    string prefix = "fixture|" + new string('A', 32) + @"|C:\BrokerTools\broker-guest-helper.exe";
                    for (int bits = 0; bits < 8; bits++)
                    {
                        var fixture = GuestFixture.PolicyLine(prefix); fixture.OwnedMutations = (bits & 1) != 0; fixture.PublicListing = (bits & 2) != 0; fixture.OwnedRenames = (bits & 4) != 0;
                        GuestFixture roundtrip = GuestFixture.PolicyLine(fixture.PolicyLine()); Assert(roundtrip.OwnedMutations == fixture.OwnedMutations && roundtrip.PublicListing == fixture.PublicListing && roundtrip.OwnedRenames == fixture.OwnedRenames);
                    }
                    foreach (string flags in new[] { "owned-rename,owned-empty", "owned-rename,owned-rename", "owned-rename,all", "owned-empty,,owned-rename" })
                        Reject(delegate { GuestFixture.PolicyLine(prefix + "|" + flags); }, "guest_fixture_policy_invalid");
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "renameFileInGuest"); Target target = runtime.Resolve("TEST-VM"); store.Add(target); CapabilityProfile policy = runtime.Policies[target.Binding]; string key = target.CredentialKey, fingerprint = policy.Fingerprint();
                        store.WritePolicy(target, policy); Assert(store.ReadPolicy(target).GuestFixtures[0].OwnedRenames);
                        policy.GuestFixtures[0].OwnedRenames = false; Assert(policy.Fingerprint() != fingerprint); store.WritePolicy(target, policy);
                        Assert(!store.ReadPolicy(target).GuestFixtures[0].OwnedRenames && target.CredentialKey == key);
                    });
                });
                Test("rename host opt-in and revoked grants stop before credentials or helper dispatch", delegate
                {
                    var missing = new FakeRuntime(); Grant(missing, "TEST-VM", "renameFileInGuest"); missing.Policies[missing.Resolve("TEST-VM").Binding].GuestFixtures[0].OwnedRenames = false;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("renameFileInGuest"), missing); }, "guest_fixture_owned_refused"); Assert(!missing.Events.Contains("connect"));
                    var cancel = new FakeRuntime { Consent = false }; Grant(cancel, "TEST-VM", "renameFileInGuest"); DenyGrant(cancel, "renameFileInGuest"); Reject(delegate { CatalogEngine.Execute(SampleCommand("renameFileInGuest"), cancel); }, "capability_not_granted"); Assert(cancel.Credential == null && !cancel.Events.Contains("prepare-private-inputs"));
                    var revoked = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(revoked, "TEST-VM", "renameFileInGuest"); Reject(delegate { CatalogEngine.Execute(SampleCommand("renameFileInGuest"), revoked); }, "capability_policy_changed"); Assert(revoked.Credential == null);
                });
                Test("rename refuses root generation corrupt-ledger and redirected source identity without mutating names", delegate
                {
                    WithRenameFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "old.txt"); string id = record.RootIdentity; record.RootIdentity = new string('0', 64);
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "guest_fixture_root_changed"); record.RootIdentity = id;
                        File.WriteAllText(Path.Combine(root, "outside.txt"), "synthetic preserved"); File.Delete(Path.Combine(root, "old.txt")); MakeFixtureLink("/H", Path.Combine(root, "old.txt"), Path.Combine(root, "outside.txt"));
                        try { Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "export_path_redirected"); } finally { File.Delete(Path.Combine(root, "old.txt")); }
                        string ledger = Path.Combine(root, "store", "owned-" + record.TargetBinding + "-" + record.Alias + "-" + record.EnrollmentId + ".json"); File.WriteAllText(ledger, "null");
                        Reject(delegate { GuestRename.Apply(store, record, "old.txt", "new.txt"); }, "guest_fixture_owned_refused"); Assert(!File.Exists(Path.Combine(root, "new.txt")));
                    });
                });
                Test("rename public result is a fixed typed ACK with no names and uncertain status is never success", delegate
                {
                    OperationReport report = OperationReport.New(SampleCommand("renameFileInGuest")); GuestFixture.Complete(report, "fixture", 0); report.Validate();
                    string json = new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json(); Assert(ResultData.Parse(json).Operation.FixtureAction == "rename-owned-file" && !json.Contains("owned.txt") && !json.Contains("renamed.txt") && !report.Exists.HasValue);
                    report.FixtureAction = "create-empty-file"; Reject(report.Validate, "worker_protocol_failed"); report.FixtureAction = "rename-owned-file";
                    report.GuestExit = 0; Reject(report.Validate, "worker_protocol_failed"); report.GuestExit = null;
                    Reject(delegate { GuestFixture.Complete(report, "fixture", FixtureProtocol.MutationUncertain); }, "guest_fixture_mutation_uncertain");
                    Reject(delegate { GuestFixture.Complete(report, "fixture", FixtureProtocol.IoFailure); }, "guest_fixture_mutation_uncertain");
                    Reject(delegate { GuestFixture.Complete(report, "fixture", FixtureProtocol.MutationRefused); }, "guest_fixture_helper_refused");
                });
                Test("approved named listing observes known public file and directory through the same retained native enumerator", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "a.txt"), "synthetic public bytes not read by enumerator"); string subdir = Path.Combine(path, "subdir"); Directory.CreateDirectory(subdir);
                        File.WriteAllText(Path.Combine(subdir, "synthetic.key"), "synthetic NOT a key");
                        try
                        {
                            int status = GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest());
                            List<PublicFixtureEntry> result = record.ApprovedListing.Result(status);
                            Assert(status == ApprovedListing.ExitBase + 3 && result.Count == 2 && result[0].Name == "a.txt" && result[1].Name == "subdir" && result[1].Kind == "directory");
                        }
                        finally { File.Delete(Path.Combine(subdir, "synthetic.key")); Directory.Delete(subdir); }
                    });
                });
                Test("approved named empty observation is a reserved bitmap and missing directory is never an empty success", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        int status = GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); Assert(status == ApprovedListing.ExitBase && record.ApprovedListing.Result(status).Count == 0);
                        record.ApprovedListing.Directory = "missing";
                        Reject(delegate { GuestListing.ObserveApproved(record, "missing", record.ApprovedListing.Digest()); }, "export_root_unavailable");
                    });
                });
                Test("unknown public-looking or secret-shaped guest entries refuse the whole approved list without returning names", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "a.txt"), ""); string extra = Path.Combine(path, "unexpected.txt"); File.WriteAllText(extra, "");
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused"); File.Delete(extra);
                        string key = Path.Combine(path, "synthetic.key"); File.WriteAllText(key, "synthetic NOT a key");
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_path_rejected");
                    });
                });
                Test("approved names and kinds are exact rather than silently substituting case or file type", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "A.txt"), "");
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused"); File.Delete(Path.Combine(path, "A.txt"));
                        Directory.CreateDirectory(Path.Combine(path, "a.txt"));
                        try { Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused"); }
                        finally { Directory.Delete(Path.Combine(path, "a.txt")); }
                    });
                });
                Test("manifest digest is order-independent but binds directory alias basename kind and slot meanings", delegate
                {
                    ApprovedListing a = ApprovedPlan(), b = ApprovedPlan(); b.Entries.Reverse(); Assert(a.Digest() == b.Digest());
                    Assert(a.Ordered()[0].Alias == "Alpha" && b.Ordered()[0].Name == "a.txt");
                    foreach (Action<ApprovedListing> change in new Action<ApprovedListing>[] {
                        delegate(ApprovedListing p) { p.Directory = "another"; }, delegate(ApprovedListing p) { p.Entries[0].Alias = "Changed"; },
                        delegate(ApprovedListing p) { p.Entries[0].Name = "b.txt"; }, delegate(ApprovedListing p) { p.Entries[0].Kind = "directory"; },
                        delegate(ApprovedListing p) { string name = p.Entries[0].Alias; p.Entries[0].Alias = p.Entries[1].Alias; p.Entries[1].Alias = name; } })
                    { b = ApprovedPlan(); change(b); Assert(a.Digest() != b.Digest()); }
                });
                Test("guest manifest mismatch or wrong directory fails before any bitmap can be interpreted by host", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "a.txt"), ""); ApprovedListing other = ApprovedPlan(); other.Entries[0].Alias = "Changed";
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", other.Digest()); }, "guest_fixture_listing_refused");
                        Reject(delegate { GuestListing.ObserveApproved(record, "Emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused");
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", "not-a-digest"); }, "guest_fixture_listing_refused");
                    });
                });
                Test("named manifest grammar rejects duplicates overflow paths key names mixed directories and unknown kinds", delegate
                {
                    foreach (string[] lines in new[] {
                        new string[0], new[] { "emptydir|A|a.txt|file", "emptydir|a|b.txt|file" }, new[] { "emptydir|A|a.txt|file", "emptydir|B|A.txt|file" },
                        new[] { "emptydir|A|a.txt|file", "other|B|b.txt|file" }, new[] { "emptydir|A|a.txt|device" }, new[] { "emptydir|A|a.txt|FILE" } })
                        Reject(delegate { ApprovedListing.ParseLines(lines); }, "guest_fixture_listing_refused");
                    foreach (string line in new[] { @"emptydir|A|a\b.txt|file", "emptydir|A|synthetic.key|file", "../bad|A|a.txt|file" })
                        Reject(delegate { ApprovedListing.ParseLines(new[] { line }); }, "guest_fixture_path_rejected");
                    var many = new List<string>(); for (int i = 0; i < 9; i++) many.Add("emptydir|A" + i + "|a" + i + ".txt|file");
                    Reject(delegate { ApprovedListing.ParseLines(many); }, "guest_fixture_listing_refused");
                });
                Test("all eight-slot masks roundtrip and legacy count ACK fatal overflow or unused bits are rejected", delegate
                {
                    var lines = new List<string>(); for (int i = 0; i < 8; i++) lines.Add("emptydir|A" + i + "|a" + i + ".txt|file"); ApprovedListing plan = ApprovedListing.ParseLines(lines);
                    for (int mask = 0; mask < 256; mask++)
                    {
                        int actual = 0; List<PublicFixtureEntry> entries = plan.Result(ApprovedListing.ExitBase + mask);
                        foreach (PublicFixtureEntry entry in entries) actual |= 1 << Int32.Parse(entry.Alias.Substring(1)); Assert(actual == mask);
                    }
                    foreach (long code in new long[] { -1, 0, 1, 20, 25, 26, 27, ListingCounts.Base, ApprovedListing.ExitBase - 1, ApprovedListing.ExitBase + 256, 0xC0000005, Int64.MaxValue })
                        Reject(delegate { plan.Decode(code); }, "guest_fixture_listing_refused");
                    plan = ApprovedPlan(); Reject(delegate { plan.Decode(ApprovedListing.ExitBase + 4); }, "guest_fixture_listing_refused");
                });
                Test("absent optional manifest preserves protocol4 old operations and never expands counts into named authority", delegate
                {
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        Assert(FixtureProtocol.Version == 4 && store.Read(record.TargetBinding, record.Alias).ApprovedListing == null);
                        Assert(GuestListing.Observe(record, "emptydir").Encode() == ListingCounts.Base);
                        Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", ApprovedPlan().Digest()); }, "guest_fixture_listing_refused");
                        record.ApprovedListing = ApprovedPlan(); record.PublicListing = false; store.Save(record);
                        Assert(GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()) == ApprovedListing.ExitBase);
                        Reject(delegate { GuestListing.Observe(record, "emptydir"); }, "guest_fixture_listing_refused");
                    });
                });
                Test("host named-plan attachment is explicit bounded atomic on parse failure and blank input revokes only names", delegate
                {
                    var fixture = GuestFixture.PolicyLine("fixture|" + new string('A', 32) + @"|C:\BrokerTools\broker-guest-helper.exe|public-counts"); var fixtures = new List<GuestFixture> { fixture };
                    GuestFixture.AttachNamedPlans(fixtures, new[] { "fixture|emptydir|Alpha|a.txt|file", "fixture|emptydir|Beta|subdir|directory" }); string digest = fixture.ApprovedListing.Digest();
                    Reject(delegate { GuestFixture.AttachNamedPlans(fixtures, new[] { "fixture|emptydir|A|a.txt|file", "unknown|emptydir|B|b.txt|file" }); }, "guest_fixture_not_approved"); Assert(fixture.ApprovedListing.Digest() == digest);
                    Reject(delegate { GuestFixture.AttachNamedPlans(fixtures, new[] { "fixture|emptydir|A|a.txt|file", "fixture|other|B|b.txt|file" }); }, "guest_fixture_listing_refused"); Assert(fixture.ApprovedListing.Digest() == digest);
                    GuestFixture.AttachNamedPlans(fixtures, new string[0]); Assert(fixture.ApprovedListing == null && fixture.PublicListing);
                });
                Test("approved names need exact host plan grant and unchanged fingerprint before credentials, no approval callback", delegate
                {
                    var missing = new FakeRuntime(); Grant(missing, "TEST-VM", "listDirectoryInGuest");
                    Reject(delegate { CatalogEngine.Execute(ApprovedRequest(), missing); }, "guest_fixture_listing_refused"); Assert(!missing.Events.Contains("connect"));
                    var cancel = new FakeRuntime { Consent = false }; GrantApproved(cancel);
                    DenyGrant(cancel, "listDirectoryInGuest"); Reject(delegate { CatalogEngine.Execute(ApprovedRequest(), cancel); }, "capability_not_granted"); Assert(cancel.Credential == null && !cancel.Events.Contains("prepare-private-inputs"));
                    var revoked = new FakeRuntime { RevokePolicyAtPrepare = true }; GrantApproved(revoked);
                    Reject(delegate { CatalogEngine.Execute(ApprovedRequest(), revoked); }, "capability_policy_changed"); Assert(revoked.Credential == null);
                    var runtime = new FakeRuntime(); GrantApproved(runtime); ResultData result = ResultData.Parse(CatalogEngine.Execute(ApprovedRequest(), runtime));
                    Assert(result.Ok && result.Operation.ApprovedEntries.Count == 1 && result.Operation.ApprovedEntries[0].Name == "a.txt" && !runtime.Events.Contains("operation-consent") && runtime.Events.Contains("vault"));
                });
                Test("approved CLI variant roundtrips with exact option and helper argv contains digest not manifest names", delegate
                {
                    VmrunRequest request = ApprovedRequest(); Assert(request.IsApprovedListing && VmrunRequest.Parse(request.Tokens()).IsApprovedListing && request.Stored);
                    var runtime = new FakeRuntime(); GrantApproved(runtime); GuestFixture fixture = runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures[0];
                    string helperArgs = fixture.Arguments(runtime.Resolve("TEST-VM"), request); Assert(helperArgs.Contains("list-approved") && helperArgs.Contains(fixture.ApprovedListing.Digest()) && !helperArgs.Contains("a.txt") && !helperArgs.Contains("Alpha"));
                    Reject(delegate { VmrunRequest.Parse(new[] { "listDirectoryInGuest", "TEST-VM", "fixture", "emptydir", "--all-names" }); }, "invalid_request");
                    Reject(delegate { VmrunRequest.Parse(new[] { "listDirectoryInGuest", "TEST-VM", "fixture", "emptydir", "--stored", "--approved" }); }, "invalid_request");
                });
                Test("approved helper request validates exact digest generation and image and never returns count status as names", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "a.txt"), ""); string[] namedArgs = { "list-approved", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir", record.ApprovedListing.Digest() };
                        Assert(GuestProbe.Request(store, record.ImageSha256, namedArgs) == ApprovedListing.ExitBase + 1);
                        foreach (int field in new[] { 3, 4, 6 })
                        { string old = namedArgs[field]; namedArgs[field] = new string('0', field == 3 ? 32 : 64); Assert(GuestProbe.Request(store, record.ImageSha256, namedArgs) < ApprovedListing.ExitBase); namedArgs[field] = old; }
                        Assert(GuestProbe.Request(store, record.ImageSha256, new[] { "list-approved", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir" }) == FixtureProtocol.Invalid);
                    });
                });
                Test("approved typed result permits only enrolled host entries and rejects mixed counts unsafe fields or wrong command", delegate
                {
                    OperationReport report = OperationReport.New(ApprovedRequest()); GuestFixture.CompleteApproved(report, "fixture", ApprovedPlan(), ApprovedListing.ExitBase + 3); report.Validate();
                    string json = new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json(); ResultData parsed = ResultData.Parse(json);
                    Assert(parsed.Operation.ApprovedEntries.Count == 2 && !json.Contains("Directory\":\"emptydir") && !json.Contains("Digest") && !json.Contains("RootPath"));
                    string human = Output.Human(parsed); Assert(human.Contains("Alpha | a.txt | file") && human.Contains("HOST manifest") && human.Contains("NOT a snapshot"));
                    report.FixtureFiles = 2; Reject(report.Validate, "worker_protocol_failed"); report.FixtureFiles = null;
                    report.Computer = "SYNTHETIC-GUEST"; Reject(report.Validate, "worker_protocol_failed"); report.Computer = null;
                    report.Tools = 2; Reject(report.Validate, "worker_protocol_failed"); report.Tools = null;
                    report.ApprovedEntries[0].Name = "synthetic.key"; Reject(report.Validate, "worker_protocol_failed"); report.ApprovedEntries[0].Name = "a.txt";
                    report.Command = "fileExistsInGuest"; Reject(report.Validate, "worker_protocol_failed");
                });
                Test("approved observation retains existing reparse hardlink locked and root identity refusals", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string id = record.RootIdentity; record.RootIdentity = new string('0', 64); Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_root_changed"); record.RootIdentity = id;
                        string a = Path.Combine(path, "a.txt"), outside = Path.Combine(record.RootPath, "outside.txt"); File.WriteAllText(outside, "synthetic public fixture"); MakeFixtureLink("/H", a, outside);
                        try { Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "export_path_redirected"); } finally { File.Delete(a); }
                        using (var file = new FileStream(a, FileMode.CreateNew, FileAccess.Write, FileShare.None)) Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused"); File.Delete(a);
                        string link = Path.Combine(path, "subdir"); MakeFixtureLink("/J", link, record.RootPath);
                        try { Reject(delegate { GuestListing.ObserveApproved(record, "emptydir", record.ApprovedListing.Digest()); }, "guest_fixture_listing_refused"); } finally { Directory.Delete(link); }
                    });
                });
                Test("named observation shares enrollment lease and sees manifest revocation with the same generation", delegate
                {
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        string[] namedArgs = { "list-approved", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir", record.ApprovedListing.Digest() };
                        using (store.MutationLock()) Assert(GuestProbe.Request(store, record.ImageSha256, namedArgs) < ApprovedListing.ExitBase);
                        Assert(GuestProbe.Request(store, record.ImageSha256, namedArgs) == ApprovedListing.ExitBase);
                        record.ApprovedListing = null; store.Save(record); Assert(GuestProbe.Request(store, record.ImageSha256, namedArgs) < ApprovedListing.ExitBase);
                    });
                });
                Test("maximum manifests fit protected bounded guest and host metadata without changing registry-v2 keys", delegate
                {
                    var lines = new List<string>(); string directory = new string('d', 48) + "\\" + new string('e', 48) + "\\" + new string('f', 30);
                    for (int i = 0; i < 8; i++) lines.Add(directory + "|A" + new string('a', 30) + i + "|n" + new string('n', 42) + i + ".txt|directory"); ApprovedListing plan = ApprovedListing.ParseLines(lines);
                    WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    { record.ApprovedListing = plan; store.Save(record); Assert(store.Read(record.TargetBinding, record.Alias).ApprovedListing.Digest() == plan.Digest()); });
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        var runtime = new FakeRuntime(); GrantApproved(runtime); Target target = runtime.Resolve("TEST-VM"); store.Add(target); string key = target.CredentialKey; CapabilityProfile policy = runtime.Policies[target.Binding]; policy.GuestFixtures.Clear();
                        for (int i = 0; i < 8; i++) policy.GuestFixtures.Add(new GuestFixture { Alias = "fixture" + i, EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = HelperBuild.Hash, ApprovedListing = plan });
                        store.WritePolicy(target, policy); Assert(store.ReadPolicy(target).GuestFixtures.Count == 8 && target.CredentialKey == key);
                        string fingerprint = policy.Fingerprint(); plan.Entries[0].Kind = "file"; Assert(fingerprint != policy.Fingerprint());
                    });
                });
                Test("named result clones host declarations and unknown guest names never enter safe error output", delegate
                {
                    ApprovedListing plan = ApprovedPlan(); string digest = plan.Digest(); List<PublicFixtureEntry> result = plan.Result(ApprovedListing.ExitBase + 1); result[0].Alias = "Changed"; Assert(plan.Digest() == digest);
                    WithApprovedFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
                    {
                        File.WriteAllText(Path.Combine(path, "unexpected-public.txt"), ""); string[] namedArgs = { "list-approved", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "emptydir", record.ApprovedListing.Digest() };
                        int code = GuestProbe.Request(store, record.ImageSha256, namedArgs); Assert(code < ApprovedListing.ExitBase);
                        Reject(delegate { GuestFixture.CompleteApproved(OperationReport.New(ApprovedRequest()), "fixture", plan, code); }, "guest_fixture_listing_refused");
                        ResultData error = ResultData.Error("guest_fixture_listing_refused", Stage.CatalogOperation); Assert(!error.Json().Contains("unexpected-public") && !Output.Human(error).Contains("unexpected-public"));
                    });
                });
                Test("oversized optional policy metadata is refused before publication and retains the prior complete grants", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        var runtime = new FakeRuntime(); GrantApproved(runtime); Target target = runtime.Resolve("TEST-VM"); store.Add(target); CapabilityProfile policy = runtime.Policies[target.Binding]; store.WritePolicy(target, policy);
                        string digest = store.ReadPolicy(target).GuestFixtures[0].ApprovedListing.Digest();
                        policy.Devices = new List<ApprovedDevice> { new ApprovedDevice { Id = "sata0:1", Fingerprint = new string('A', 64), MediaIdentity = new string('B', 64), MediaPath = "D:\\SyntheticFixture\\" + new string('x', 40000) + ".iso" } };
                        Reject(delegate { store.WritePolicy(target, policy); }, "capability_policy_invalid");
                        CapabilityProfile retained = store.ReadPolicy(target); Assert(retained.Devices == null && retained.GuestFixtures[0].ApprovedListing.Digest() == digest && Directory.GetFiles(root, "policy.new.*").Length == 0);
                    });
                });
                Test("whole owned-file deletion destroys nonzero test data and test stream, preserves tombstone and creation cap", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "owned.txt"); File.WriteAllText(Path.Combine(root, "owned.txt"), "generated public test data");
                        var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                        using (var handle = Native.CreateFileW(Path.Combine(root, "owned.txt") + ":public-fixture", 0x40000000, 1, ref security, 1, 0, IntPtr.Zero))
                        using (var stream = new FileStream(handle, FileAccess.Write)) stream.WriteByte(42);
                        GuestDelete.Apply(store, record, "owned.txt", false);
                        Assert(!File.Exists(Path.Combine(root, "owned.txt")) && store.ReadOwned(record).Items.Count == 1 && store.ReadOwned(record).Items[0].Deleted);
                        Reject(delegate { GuestOwned.Apply(store, record, "create-empty-file", "owned.txt"); }, "guest_fixture_create_refused");
                        Reject(delegate { GuestDelete.Apply(store, record, "owned.txt", false); }, "guest_fixture_owned_refused");
                    });
                });
                Test("whole owned-tree deletion preflights nested owned descendants and destroys them only through retained handles", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); GuestOwned.Apply(store, record, "create-directory", @"emptydir\dest"); GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\dest\data.txt");
                        File.WriteAllText(Path.Combine(root, "emptydir", "dest", "data.txt"), "public test bytes");
                        GuestDelete.Apply(store, record, "emptydir", true);
                        Assert(!Directory.Exists(Path.Combine(root, "emptydir")) && store.ReadOwned(record).Items.TrueForAll(delegate (OwnedFixture item) { return item.Deleted; }));
                    });
                });
                Test("foreign tree child refuses before any owned descendant or tombstone is changed", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\owned.txt");
                        string foreign = Path.Combine(root, "emptydir", "foreign.txt"); File.WriteAllText(foreign, "synthetic preserved");
                        Reject(delegate { GuestDelete.Apply(store, record, "emptydir", true); }, "guest_fixture_owned_refused");
                        Assert(File.Exists(Path.Combine(root, "emptydir", "owned.txt")) && File.ReadAllText(foreign) == "synthetic preserved" && store.ReadOwned(record).Items.TrueForAll(delegate (OwnedFixture item) { return !item.Deleted; }));
                    });
                });
                Test("delete intent is persisted before first destruction and partial failure never restores stale ownership", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\owned.txt");
                        Reject(delegate { GuestDelete.Apply(store, record, "emptydir", true, null, null, delegate { throw new IOException("synthetic after-first-delete"); }); }, "guest_fixture_mutation_uncertain");
                        Assert(Directory.Exists(Path.Combine(root, "emptydir")) && !File.Exists(Path.Combine(root, "emptydir", "owned.txt")) && store.ReadOwned(record).Items.TrueForAll(delegate (OwnedFixture item) { return item.Deleted; }));
                        Reject(delegate { GuestDelete.Apply(store, record, "emptydir", true); }, "guest_fixture_owned_refused");
                    });
                });
                Test("delete publication failure leaves objects present and never reports success or clears foreign data", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "owned.txt");
                        Reject(delegate { GuestDelete.Apply(store, record, "owned.txt", false, null, delegate { throw new IOException("synthetic intent publication"); }); }, "guest_fixture_mutation_uncertain");
                        Assert(File.Exists(Path.Combine(root, "owned.txt")) && !store.ReadOwned(record).Items[0].Deleted);
                    });
                });
                Test("whole deletion requires independent grants and denies SAFE-DC before native connect or credentials", delegate
                {
                    foreach (string command in new[] { "deleteFileInGuest", "deleteDirectoryInGuest" })
                    {
                        var missing = new FakeRuntime(); Grant(missing, "TEST-VM", command); missing.Policies[missing.Resolve("TEST-VM").Binding].GuestFixtures[0].OwnedDeletes = false;
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(command), missing); }, "guest_fixture_owned_refused"); Assert(!missing.Events.Contains("connect"));
                        var cancel = new FakeRuntime { Consent = false }; Grant(cancel, "TEST-VM", command); DenyGrant(cancel, command); Reject(delegate { CatalogEngine.Execute(SampleCommand(command), cancel); }, "capability_not_granted"); Assert(cancel.Credential == null);
                        var protectedVm = new FakeRuntime(); Grant(protectedVm, "SAFE-DC", command); VmrunRequest request = SampleCommand(command); request.TargetName = "SAFE-DC";
                        Reject(delegate { CatalogEngine.Execute(request, protectedVm); }, "protected_target_refused"); Assert(!protectedVm.Events.Contains("connect"));
                    }
                });
                Test("delete source ID replacement hardlinks and readonly changes refuse without losing ownership records", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-empty-file", "owned.txt"); string path = Path.Combine(root, "owned.txt"); File.SetAttributes(path, FileAttributes.ReadOnly);
                        try { Reject(delegate { GuestDelete.Apply(store, record, "owned.txt", false); }, "guest_fixture_owned_refused"); } finally { File.SetAttributes(path, FileAttributes.Normal); }
                        File.WriteAllText(Path.Combine(root, "replacement.txt"), ""); File.Replace(Path.Combine(root, "replacement.txt"), path, null);
                        Reject(delegate { GuestDelete.Apply(store, record, "owned.txt", false); }, "guest_fixture_owned_refused"); Assert(!store.ReadOwned(record).Items[0].Deleted);
                    });
                });
                Test("delete and process rights are explicit optional flags, no old count/create/rename grant implies them", delegate
                {
                    string prefix = "fixture|" + new string('A', 32) + @"|C:\BrokerTools\broker-guest-helper.exe";
                    for (int bits = 0; bits < 32; bits++)
                    {
                        GuestFixture fixture = GuestFixture.PolicyLine(prefix); fixture.OwnedMutations = (bits & 1) != 0; fixture.PublicListing = (bits & 2) != 0; fixture.OwnedRenames = (bits & 4) != 0; fixture.OwnedDeletes = (bits & 8) != 0; fixture.OwnedProcesses = (bits & 16) != 0;
                        GuestFixture read = GuestFixture.PolicyLine(fixture.PolicyLine()); Assert(read.OwnedDeletes == fixture.OwnedDeletes && read.OwnedProcesses == fixture.OwnedProcesses && read.PolicyLine() == fixture.PolicyLine());
                    }
                    Reject(delegate { GuestFixture.PolicyLine(prefix + "|owned-process,owned-delete"); }, "guest_fixture_policy_invalid");
                });
                Test("native owned fixture supervisor starts fixed self image and stops only its retained idle child", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000);
                        FixtureProcessRecord process = store.ReadProcess(record, "slot1");
                        IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, process.Supervisor);
                        try { Assert(view != IntPtr.Zero && Native.WaitForSingleObject(view, 0) == 258); GuestProcessSupervisor.Stop(store, record, "slot1"); Assert(Native.WaitForSingleObject(view, 5000) == 0); }
                        finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                        Assert(!store.ProcessExists(record, "slot1"));
                    });
                });
                Test("owned fixture process expires without a caller kill or an arbitrary PID cleanup", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 1000); FixtureProcessRecord process = store.ReadProcess(record, "slot1");
                        IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, process.Supervisor);
                        try { Assert(view != IntPtr.Zero && Native.WaitForSingleObject(view, 5000) == 0); } finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                        Assert(!store.ProcessExists(record, "slot1"));
                    });
                });
                Test("guest process right revocation terminates only the owned fixture and invalidates its slot", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000); FixtureProcessRecord process = store.ReadProcess(record, "slot1");
                        IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, process.Supervisor); record.OwnedProcesses = false; store.Save(record);
                        try { Assert(view != IntPtr.Zero && Native.WaitForSingleObject(view, 5000) == 0); } finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                        Reject(delegate { GuestProcessSupervisor.Stop(store, record, "slot1"); }, "guest_fixture_process_refused");
                    });
                });
                Test("fixture CLI rejects arbitrary PID and programs while fixed process ACK contains no PID or paths", delegate
                {
                    VmrunRequest start = VmrunRequest.Parse(new[] { "runProgramInGuest", "TEST-VM", "BROKER_PUBLIC_FIXTURE", "--stored", "--", "fixture", "slot1" }); Assert(start.IsFixtureStart);
                    Reject(delegate { VmrunRequest.Parse(new[] { "killProcessInGuest", "TEST-VM", "123" }); }, "invalid_request");
                    Reject(delegate { VmrunRequest.Parse(new[] { "killProcessInGuest", "TEST-VM", "fixture", "123", "--stored" }); }, "guest_fixture_process_refused");
                    OperationReport report = OperationReport.New(start); GuestFixture.CompleteProcess(report, start, "fixture", 0); report.Validate();
                    string json = new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json(); Assert(ResultData.Parse(json).Operation.FixtureProcessSlot == "slot1" && !json.Contains("Supervisor") && !json.Contains("Created") && !json.Contains("HelperPath") && !report.GuestExit.HasValue);
                });
                Test("duplicate fixture slot refuses without adopting or replacing the already retained process", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000); FixtureProcessRecord before = store.ReadProcess(record, "slot1");
                        Reject(delegate { GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000); }, "guest_fixture_process_refused");
                        Assert(store.ReadProcess(record, "slot1").Instance == before.Instance);
                        try { GuestProcessSupervisor.Stop(store, record, "slot1"); }
                        catch (BrokerError error)
                        {
                            IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, before.Supervisor); uint status = 0xffffffff;
                            try { if (view != IntPtr.Zero) Native.GetExitCodeProcess(view, out status); } finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                            Console.WriteLine("SYNTHETIC duplicate-slot stop failure: supervisor-status=0x" + status.ToString("X8") + "; safe-phase=" + (error.Data["FixtureSafePhase"] is int ? error.Data["FixtureSafePhase"] : 0)); throw;
                        }
                    });
                });
                Test("changed supervisor creation identity refuses before control and cannot become PID termination authority", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000); FixtureProcessRecord meta = store.ReadProcess(record, "slot1"); long created = meta.Created;
                        string path = Path.Combine(root, "store", "process-" + FixtureProcessRecord.Context(record, "slot1") + ".json");
                        Action publish = delegate { using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)) new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(FixtureProcessRecord)).WriteObject(file, meta); };
                        try
                        {
                            meta.Created++; publish(); Reject(delegate { GuestProcessSupervisor.Stop(store, record, "slot1"); }, "guest_fixture_process_refused");
                            Assert(meta.Supervisor != (uint)System.Diagnostics.Process.GetCurrentProcess().Id);
                        }
                        finally { meta.Created = created; publish(); }
                        GuestProcessSupervisor.Stop(store, record, "slot1");
                    });
                });
                Test("fixture start requires scoped permission and post-operation cleanup never becomes false success unattended", delegate
                {
                    VmrunRequest start = VmrunRequest.Parse(new[] { "runProgramInGuest", "TEST-VM", "BROKER_PUBLIC_FIXTURE", "--stored", "--", "fixture", "slot1" });
                    var runtime = new FakeRuntime { Consent = false }; Grant(runtime, "TEST-VM", "runProgramInGuest"); Target target = runtime.Resolve("TEST-VM");
                    runtime.Policies[target.Binding].GuestFixtures = new List<GuestFixture> { new GuestFixture { Alias = "fixture", EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = HelperBuild.Hash, OwnedProcesses = true } };
                    DenyGrant(runtime, "runProgramInGuest"); Reject(delegate { CatalogEngine.Execute(start, runtime); }, "capability_not_granted"); Assert(runtime.Credential == null);
                    runtime.Policies[target.Binding].Commands.Add("runProgramInGuest"); runtime.FailDispose = true; Reject(delegate { CatalogEngine.Execute(start, runtime); }, "guest_fixture_mutation_uncertain"); Assert(runtime.Credential.Password.Pointer == IntPtr.Zero);
                });
                Test("late foreign tree child is not deleted and forces unknown after any owned children were removed", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); GuestOwned.Apply(store, record, "create-empty-file", @"emptydir\owned.txt");
                        Action late = delegate
                        {
                            var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                            using (var parent = Native.CreateFileW(Path.Combine(root, "emptydir"), 0x80, 7, ref security, 3, 0x02000000 | 0x00200000, IntPtr.Zero))
                            { Assert(!parent.IsInvalid); using (var foreign = OwnedNative.Create(parent, "foreign.txt", false)) HostPaths.CheckHandle(foreign, Path.Combine(root, "emptydir", "foreign.txt"), false); }
                        };
                        Reject(delegate { GuestDelete.Apply(store, record, "emptydir", true, late); }, "guest_fixture_mutation_uncertain");
                        Assert(File.Exists(Path.Combine(root, "emptydir", "foreign.txt")) && Directory.Exists(Path.Combine(root, "emptydir")) && store.ReadOwned(record).Items.TrueForAll(delegate (OwnedFixture item) { return item.Deleted; }));
                    });
                });
                Test("owned directory test streams are authorized whole-object data, not an empty-directory bypass", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        GuestOwned.Apply(store, record, "create-directory", "emptydir"); var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                        using (var handle = Native.CreateFileW(Path.Combine(root, "emptydir") + ":public-fixture", 0x40000000, 1, ref security, 1, 0, IntPtr.Zero))
                        using (var file = new FileStream(handle, FileAccess.Write)) file.WriteByte(17);
                        GuestDelete.Apply(store, record, "emptydir", true); Assert(!Directory.Exists(Path.Combine(root, "emptydir")) && store.ReadOwned(record).Items[0].Deleted);
                    });
                });
                Test("generated public fixture factory creates and verifies one MiB without importing or returning caller bytes", delegate
                {
                    WithDeleteFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        record.GeneratedFixtures = true; store.Save(record); string id = new string('A', 32);
                        GeneratedFixture.Create(store, record, "generated.bin", "1048576", id); string path = Path.Combine(root, "generated.bin");
                        Assert(new FileInfo(path).Length == GeneratedFixture.Maximum); HostPaths.CheckPrivateFile(path);
                        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) GeneratedFixture.Verify(file, id, GeneratedFixture.Maximum);
                        OwnedFixture meta = store.ReadOwned(record).Items[0]; Assert(meta.GeneratedId == id && meta.GeneratedBytes == GeneratedFixture.Maximum);
                        GuestDelete.Apply(store, record, "generated.bin", false); Assert(!File.Exists(path) && store.ReadOwned(record).Items[0].Deleted);
                    });
                });
                Test("generated fixture refuses imports tampering oversized noncanonical sizes and existing names", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        record.GeneratedFixtures = true; store.Save(record); string id = new string('B', 32); GeneratedFixture.Create(store, record, "generated.bin", "64", id);
                        Reject(delegate { GeneratedFixture.Create(store, record, "generated.bin", "64", id); }, "guest_fixture_create_refused");
                        foreach (string size in new[] { "0", "-1", "001", "1048577", "anything" }) Reject(delegate { GeneratedFixture.Size(size); }, "guest_fixture_generated_refused");
                        using (var file = new FileStream(Path.Combine(root, "generated.bin"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        { file.Position = 0; file.WriteByte(0); file.Flush(); Reject(delegate { GeneratedFixture.Verify(file, id, 64); }, "guest_fixture_generated_refused"); }
                    });
                });
                Test("generated data is a new separately granted variant, not an expansion of empty-file permission", delegate
                {
                    VmrunRequest request = VmrunRequest.Parse(new[] { "CreateTempfileInGuest", "TEST-VM", "fixture", "generated.bin", "--generated", "64", "--stored" }); Assert(request.IsGeneratedFixture);
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "CreateTempfileInGuest");
                    Reject(delegate { CatalogEngine.Execute(request, runtime); }, "guest_fixture_owned_refused"); Assert(!runtime.Events.Contains("connect"));
                    runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures[0].GeneratedFixtures = true;
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(request, runtime)); Assert(result.Operation.FixtureGeneratedBytes == 64 && FixtureProtocol.Hex(result.Operation.FixtureGeneratedId, 32) && result.Operation.FixtureAction == "create-generated-file");
                    OperationReport report = result.Operation; report.FixtureGeneratedBytes = GeneratedFixture.Maximum + 1; Reject(report.Validate, "worker_protocol_failed");
                });
                Test("generated helper opcode requires the explicit eight-field recipe and refuses an absent guest grant", delegate
                {
                    WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        string[] generatedArgs = { "create-generated-file", record.TargetBinding, record.Alias, record.EnrollmentId, record.ImageSha256, "generated.bin", "64", new string('C', 32) };
                        Assert(GuestProbe.Request(store, record.ImageSha256, generatedArgs) == FixtureProtocol.MutationRefused);
                        record.GeneratedFixtures = true; store.Save(record); Assert(GuestProbe.Request(store, record.ImageSha256, generatedArgs) == 0 && new FileInfo(Path.Combine(root, "generated.bin")).Length == 64);
                    });
                });
                Test("fixture processes receive only a minimal generated public directory environment, never a cloned caller block", delegate
                {
                    string block = OwnedFixtureProcess.PublicEnvironment(); Assert(block.EndsWith("\0\0", StringComparison.Ordinal));
                    var names = new HashSet<string>(new[] { "SystemRoot", "WINDIR", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "TEMP", "TMP", "PATH" }, StringComparer.OrdinalIgnoreCase);
                    foreach (string entry in block.Split('\0')) if (entry.Length != 0) { int split = entry.IndexOf('='); Assert(split > 0 && names.Remove(entry.Substring(0, split))); }
                    Assert(names.Count == 0 && !block.Contains("PASSWORD=") && !block.Contains("TOKEN=") && !block.Contains("COMPlus_"));
                });
                Test("public fixture sink model refuses missing focus and accepts only its fixed alphanumeric sample", delegate
                {
                    string received = ""; uint denied = PublicFixtureSink.Accept(4, false, delegate (string text) { received += text; }); Assert(denied == 4 && received == "");
                    uint accepted = PublicFixtureSink.Accept(4, true, delegate (string text) { received += text; }); Assert(accepted == 2 && received == PublicFixtureSink.Sample && received.Length <= 32);
                    foreach (char character in received) Assert((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-');
                    Reject(delegate { PublicFixtureSink.SampleName("arbitrary typed data"); }, "guest_fixture_process_refused");
                    Reject(delegate { PublicFixtureSink.Accept(5, true, delegate { }); }, "guest_fixture_process_refused");
                });
                Test("headless owned-child private input protocol delivers only a fixed public sample, NOT real GUI focus validation", delegate
                {
                    WithProcessFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
                    {
                        record.OwnedSink = true; store.Save(record); GuestProcessSupervisor.StartForTest(store, record, "slot1", Path.Combine(root, "store"), 5000);
                        GuestProcessSupervisor.Type(store, record, "slot1", "PUBLIC_ALNUM"); GuestProcessSupervisor.Stop(store, record, "slot1");
                    });
                });
                Test("public sink CLI and host grants never accept raw text arbitrary windows or clipboard fallback", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "typeKeystrokesInGuest"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures[0].OwnedSink = false;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("typeKeystrokesInGuest"), runtime); }, "guest_fixture_process_refused"); Assert(!runtime.Events.Contains("connect"));
                    Reject(delegate { VmrunRequest.Parse(new[] { "typeKeystrokesInGuest", "TEST-VM", "fixture", "slot1", "ANY-OTHER-TEXT" }); }, "guest_fixture_process_refused");
                    OperationReport result = OperationReport.New(SampleCommand("typeKeystrokesInGuest")); GuestFixture.CompleteProcess(result, SampleCommand("typeKeystrokesInGuest"), "fixture", 0); result.Validate(); Assert(!new ResultData { Ok = true, Target = "TEST-VM", Operation = result }.Json().Contains(PublicFixtureSink.Sample));
                });
                Test("unattended CLI revalidates configured policy and never calls any operation approval callback", delegate
                {
                    var permitted = new FakeRuntime { Consent = false }; Grant(permitted, "TEST-VM", "getGuestIPAddress");
                    Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand("getGuestIPAddress"), permitted)).Ok && !permitted.Events.Contains("operation-consent") && !permitted.Events.Contains("host-read-consent") && permitted.Credential == null);
                    var revoked = new FakeRuntime { RevokePolicyAtSecondRead = true }; Grant(revoked, "TEST-VM", "getGuestIPAddress");
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("getGuestIPAddress"), revoked); }, "capability_policy_changed"); Assert(!revoked.Events.Contains("official-cli:getGuestIPAddress") && revoked.Credential == null);
                });
                Test("risk metadata remains independent of deferred operation prompts and historical consent stages no longer pause deadlines", delegate
                {
                    Assert(!OperationAuthorization.RequiresPrompt && OperationAuthorization.PromptStatus == "deferred-policy-required");
                    foreach (CatalogEntry row in Catalog.Entries) Assert(!row.NeedsConsent && row.SensitiveRisk == (row.Risk != "metadata"));
                    Assert(!Diagnostics.UserWait(Stage.OperationConsent) && !Diagnostics.UserWait(Stage.HostReadConsent) && !Diagnostics.UserWait(Stage.TimezoneConsent));
                    Assert(Diagnostics.UserWait(Stage.CredentialPrompt) && Diagnostics.UserWait(Stage.CapabilityPrompt) && Diagnostics.UserWait(Stage.RegistrationPrompt));
                });
                Test("optional unattended timezone setup grant preserves old policy shape and saved credential keys", delegate
                {
                    WithRegistry(delegate (string root, RegistryStore store)
                    {
                        Target target = Synthetic("TEST-VM", '2'); store.Add(target); string key = target.CredentialKey; CapabilityProfile profile = CapabilityProfile.Default(target); store.WritePolicy(target, profile);
                        Assert(!store.ReadPolicy(target).TimezoneMelbourne && target.CredentialKey == key); profile.Disposable = true; profile.TimezoneMelbourne = true; store.WritePolicy(target, profile);
                        Assert(store.ReadPolicy(target).TimezoneMelbourne && target.CredentialKey == key);
                    });
                });
                Test("known-VM rebind preserves immutable v2 credential policy and helper bindings across same-UUID rewrites", delegate
                {
                    WithVmxFixture(delegate (string path, string original, Target captured)
                    {
                        captured.IdentityMode = null; captured.ObservedFileIdentity = null; captured.IdentityRevision = 0;
                        WithRegistry(delegate (string root, RegistryStore store)
                        {
                            store.Add(captured); string key = captured.CredentialKey, binding = captured.Binding; CapabilityProfile policy = CapabilityProfile.Default(captured); policy.Commands.Add("listSnapshots");
                            policy.GuestFixtures = new List<GuestFixture> { new GuestFixture { Alias = "fixture3", EnrollmentId = "4267F29022BC4C388BAE7D8859C5959C", HelperPath = @"D:\broker-guest-helper.exe", ImageSha256 = "4FBF8C7B98936992E79215DECDE57FF7EBDE770D675E9CC48FB914ED8C350D23", OwnedMutations = true, PublicListing = true } }; store.WritePolicy(captured, policy);
                            File.WriteAllText(path + ".new", original); File.Replace(path + ".new", path, null);
                            Reject(delegate { using (VmIdentity.Open(captured)) { } }, "vm_identity_changed_reenroll_required");
                            Target current = store.RefreshKnownVm(captured.Name, binding);
                            Assert(current.CredentialKey == key && current.Binding == binding && current.FileIdentity == captured.FileIdentity && current.Generation == captured.Generation && current.IdentityRevision == 1 && store.ReadPolicy(current).Commands.Contains("listSnapshots"));
                            Assert(store.ReadPolicy(current).GuestFixtures[0].EnrollmentId == policy.GuestFixtures[0].EnrollmentId && store.ReadPolicy(current).GuestFixtures[0].ImageSha256 == policy.GuestFixtures[0].ImageSha256);
                            using (VmIdentity.Open(current)) { }
                            File.WriteAllText(path + ".new", original); File.Replace(path + ".new", path, null);
                            using (VmIdentity.Open(current)) { } // Normal subsequent rewrite needs no key rotation or per-op registry mutation.
                            Target updated = store.RefreshKnownVm(current.Name, binding); Assert(updated.IdentityRevision == 2 && updated.Binding == binding && updated.CredentialKey == key);
                        });
                    });
                });
                Test("logical VMX mode rejects changed UUID and path redirection and never silently changes a registration", delegate
                {
                    WithVmxFixture(delegate (string path, string original, Target captured)
                    {
                        using (VmIdentity.Open(captured)) { }
                        File.WriteAllText(path, "uuid.bios = \"" + new string('F', 32) + "\"\n");
                        Reject(delegate { using (VmIdentity.Open(captured)) { } }, "vm_identity_changed_reenroll_required");
                        WithRegistry(delegate (string root, RegistryStore store)
                        { store.Add(captured); Reject(delegate { store.RefreshKnownVm(captured.Name, captured.Binding); }, "vm_identity_changed_reenroll_required"); Assert(store.Read().Resolve(captured.Name).IdentityRevision == 1); });
                        File.WriteAllText(path, original); Target wrongPath = captured.Clone(); wrongPath.Vmx = path + ".other.vmx";
                        Assert(wrongPath.Binding != captured.Binding);
                    });
                });
                Test("metadata refresh requires exact binding and no native credential or operation UI is invoked", delegate
                {
                    WithVmxFixture(delegate (string path, string original, Target captured)
                    {
                        WithRegistry(delegate (string root, RegistryStore store)
                        {
                            store.Add(captured); var runtime = new FakeRuntime { MetadataRefresh = store.RefreshKnownVm };
                            Request request = RequestFor("rebind-knownvm", captured.Name, "--expect-binding", captured.Binding, "--json"); Assert(Request.Parse(request.WorkerArguments()).ExpectedBinding == captured.Binding);
                            ResultData result = ResultData.Parse(Broker.Execute(request, runtime)); Assert(result.IdentityBaseline == "path_uuid_v1" && result.RegistrationBinding == captured.Binding && String.Join(",", runtime.Events) == "metadata-refresh");
                            Reject(delegate { store.RefreshKnownVm(captured.Name, new string('0', 64)); }, "registration_changed");
                            Reject(delegate { store.RefreshKnownVm("SAFE-DC", captured.Binding); }, "protected_target_refused");
                        });
                    });
                });
                Test("refresh pins the VMX through registry publication and failed metadata publish retains the previous version", delegate
                {
                    WithVmxFixture(delegate (string path, string original, Target captured)
                    {
                        captured.IdentityMode = null; captured.ObservedFileIdentity = null; captured.IdentityRevision = 0;
                        WithRegistry(delegate (string root, RegistryStore store)
                        {
                            store.Add(captured); File.WriteAllText(path + ".new", original); bool pinHeld = false;
                            var failing = new RegistryStore(root, delegate
                            {
                                try { File.Replace(path + ".new", path, null); } catch (IOException) { pinHeld = true; }
                                throw new IOException("synthetic metadata publish failure");
                            });
                            bool refused = false; try { failing.RefreshKnownVm(captured.Name, captured.Binding); } catch (IOException) { refused = true; }
                            Target retained = store.Read().Resolve(captured.Name); Assert(refused && pinHeld && retained.IdentityMode == null && retained.Binding == captured.Binding && Directory.GetFiles(root, "registry.new.*").Length == 0);
                        });
                    });
                });
                Test("changing only registration metadata revision mid-request stops before credentials despite stable key", delegate
                {
                    var runtime = new FakeRuntime { RebindMetadataAtPrepare = true }; Grant(runtime, "TEST-VM", "runProgramInGuest"); string key = runtime.Resolve("TEST-VM").CredentialKey;
                    Reject(delegate { CatalogEngine.Execute(SampleCommand("runProgramInGuest"), runtime); }, "capability_policy_changed"); Assert(runtime.Credential == null && runtime.Resolve("TEST-VM").CredentialKey == key);
                });
                Test("reviewed protocol3 receipt remains usable only for unchanged operations and cannot authorize new helper features", delegate
                {
                    var fixture = new GuestFixture { Alias = "fixture", EnrollmentId = "4267F29022BC4C388BAE7D8859C5959C", HelperPath = @"D:\broker-guest-helper.exe", ImageSha256 = "4FBF8C7B98936992E79215DECDE57FF7EBDE770D675E9CC48FB914ED8C350D23", PublicListing = true, OwnedMutations = true };
                    fixture.Validate(); fixture.DemandImage(SampleCommand("fileExistsInGuest")); fixture.DemandImage(SampleCommand("listDirectoryInGuest"));
                    Assert(fixture.Arguments(Synthetic("TEST-VM", '2'), SampleCommand("fileExistsInGuest")).Contains(fixture.ImageSha256));
                    foreach (string command in new[] { "deleteFileInGuest", "killProcessInGuest", "renameFileInGuest", "typeKeystrokesInGuest" }) Reject(delegate { fixture.DemandImage(SampleCommand(command)); }, "guest_fixture_image_unavailable");
                    Reject(delegate { fixture.DemandImage(ApprovedRequest()); }, "guest_fixture_image_unavailable");
                    Assert(GuestFixture.SetupLine(fixture.PolicyLine(), new List<GuestFixture> { fixture }).ImageSha256 == fixture.ImageSha256);
                    fixture.ImageSha256 = new string('0', 64); fixture.Validate(); Reject(delegate { fixture.DemandImage(SampleCommand("fileExistsInGuest")); }, "guest_fixture_image_unavailable");
                });
                Test("outdated helper receipt does not block native metadata that never invokes that helper", delegate
                {
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "checkToolsState"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures = new List<GuestFixture> { new GuestFixture { Alias = "legacy", EnrollmentId = new string('A', 32), HelperPath = @"D:\broker-guest-helper.exe", ImageSha256 = new string('0', 64) } };
                    Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand("checkToolsState"), runtime)).Ok && runtime.Credential == null && !runtime.Events.Contains("operation-consent"));
                });
                Test("VMX refresh rejects real synthetic junction ancestors and linked files, never treating them as a known-VM rewrite", delegate
                {
                    WithVmxFixture(delegate (string path, string original, Target captured)
                    {
                        string link = Path.Combine(Path.GetDirectoryName(path), "vmx-junction-" + Guid.NewGuid().ToString("N")); MakeFixtureLink("/J", link, Path.GetDirectoryName(path));
                        try { Target redirected = captured.Clone(); redirected.Vmx = Path.Combine(link, Path.GetFileName(path)); Reject(delegate { using (VmIdentity.OpenLogical(redirected)) { } }, "export_path_redirected"); }
                        finally { Directory.Delete(link); }
                        string hard = path + ".linked.vmx"; MakeFixtureLink("/H", hard, path);
                        try
                        {
                            WithRegistry(delegate (string root, RegistryStore store) { store.Add(captured); Reject(delegate { store.RefreshKnownVm(captured.Name, captured.Binding); }, "export_path_redirected"); Assert(store.Read().Resolve(captured.Name).IdentityRevision == captured.IdentityRevision); });
                        }
                        finally { File.Delete(hard); }
                    });
                });
                Test("native public transfer grammar bounds bytes and rejects paths secrets unknown IDs and options", delegate
                {
                    foreach (string name in new[] { "CopyFileFromHostToGuest", "CopyFileFromGuestToHost" })
                    {
                        VmrunRequest request = SampleCommand(name); Assert(request.Stored && request.NeedsCredential && request.Entry.NeedsDisposable);
                        Assert(VmrunRequest.Parse(request.Tokens()).Arguments.Length == request.Arguments.Length);
                    }
                    foreach (string size in new[] { "0", "1048577", "-1", "01", "1.0", "--password=synthetic" })
                        Reject(delegate { VmrunRequest.Parse(new[] { "CopyFileFromHostToGuest", "TEST-VM", "public", size }); }, "guest_fixture_generated_refused");
                    Reject(delegate { VmrunRequest.Parse(new[] { "CopyFileFromGuestToHost", "TEST-VM", "public", new string('a', 32), "32" }); }, "transfer_request_invalid");
                    foreach (string path in new[] { @"C:\", @"C:\Windows", @"C:\Windows\Temp", @"C:\Users", @"C:\ProgramData\Private", @"C:\public\..\outside", @"C:\public\NUL", @"C:\public\x:stream", @"\\host\share", @"C:\public\token" })
                        Reject(delegate { PublicTransferRoot.GuestPath(path); }, "transfer_policy_invalid");
                });
                Test("transfer rights are absent by default; denial protected target and revocation precede any credential access", delegate
                {
                    foreach (string name in new[] { "CopyFileFromHostToGuest", "CopyFileFromGuestToHost" })
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", name); runtime.Policies[runtime.Resolve("TEST-VM").Binding].Transfers = null;
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "transfer_not_approved"); Assert(runtime.Credential == null && !runtime.Events.Contains("connect"));
                        runtime = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(runtime, "TEST-VM", name);
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "capability_policy_changed"); Assert(runtime.Credential == null);
                        runtime = new FakeRuntime(); Grant(runtime, "SAFE-DC", name); VmrunRequest request = SampleCommand(name); request.TargetName = "SAFE-DC";
                        Reject(delegate { CatalogEngine.Execute(request, runtime); }, "protected_target_refused"); Assert(runtime.Credential == null);
                    }
                });
                Test("public transfer executes actual local source-upload-roundtrip-download bytes at the one-MiB bound, not regeneration", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative native)
                    {
                        Target target = Synthetic("TEST-VM", '2'); VmrunRequest upload = VmrunRequest.Parse(new[] { "CopyFileFromHostToGuest", target.Name, policy.Alias, "1048576", "--stored" });
                        string id;
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, upload))
                        {
                            id = prepared.Id; var report = OperationReport.New(upload); PublicTransfers.Execute(upload, prepared, native, report); report.Validate();
                            Assert(report.TransferBytes == 1048576 && native.Copies == 2 && File.Exists(prepared.ReceivePath));
                            Assert(new ResultData { Ok = true, Target = target.Name, Operation = report }.Json().IndexOf(policy.Host.Path, StringComparison.Ordinal) < 0);
                            Assert(new FileInfo(prepared.SourcePath).Length == 1048576 && new FileInfo(native.PathFor(prepared.GuestFile)).Length == 1048576);
                            bool sourcePinned = false; try { using (var writer = File.OpenWrite(prepared.SourcePath)) { } } catch (IOException) { sourcePinned = true; }
                            Assert(sourcePinned);
                        }
                        VmrunRequest download = VmrunRequest.Parse(new[] { "CopyFileFromGuestToHost", target.Name, policy.Alias, id, "1048576", "--stored" });
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, download))
                        {
                            var report = OperationReport.New(download); PublicTransfers.Execute(download, prepared, native, report); report.Validate(); Assert(native.Copies == 3 && report.Completion == "public_transfer_received_verified");
                        }
                    });
                });
                Test("transfer guest collisions and directory or symlink root metadata refuse before native copying", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative native)
                    {
                        VmrunRequest request = SampleCommand("CopyFileFromHostToGuest"); Target target = Synthetic("TEST-VM", '2');
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, request))
                        {
                            File.WriteAllText(native.PathFor(prepared.GuestFile), "SYNTHETIC-FOREIGN-PUBLIC");
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_destination_exists");
                            Assert(native.Copies == 0 && File.ReadAllText(native.PathFor(prepared.GuestFile)) == "SYNTHETIC-FOREIGN-PUBLIC");
                            native.RootFlags = 3;
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_source_refused"); Assert(native.Copies == 0);
                        }
                    });
                });
                Test("received tamper or partial native copy fails UNKNOWN with residues retained, no retry or cleanup", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative native)
                    {
                        VmrunRequest request = SampleCommand("CopyFileFromHostToGuest"); Target target = Synthetic("TEST-VM", '2');
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, request))
                        {
                            native.TamperReceive = true;
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_outcome_unknown");
                            Assert(native.Copies == 2 && File.Exists(prepared.SourcePath) && File.Exists(prepared.ReceivePath) && File.Exists(native.PathFor(prepared.GuestFile)));
                        }
                        request = SampleCommand("CopyFileFromHostToGuest");
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, request))
                        {
                            native.FailCopy = true; int previous = native.Copies;
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_outcome_unknown"); Assert(native.Copies == previous + 1 && File.Exists(prepared.SourcePath));
                        }
                    });
                });
                Test("download preflight rejects wrong size flags and cross-target root receipts; host source tampering cannot become transfer", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative native)
                    {
                        Target target = Synthetic("TEST-VM", '2'); VmrunRequest upload = SampleCommand("CopyFileFromHostToGuest"); string id, source;
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, upload))
                        { id = prepared.Id; source = prepared.SourcePath; PublicTransfers.Execute(upload, prepared, native, OperationReport.New(upload)); }
                        VmrunRequest request = VmrunRequest.Parse(new[] { "CopyFileFromGuestToHost", target.Name, "public", id, "32" });
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, request))
                        {
                            int copies = native.Copies; native.FileFlags = 2;
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_source_refused");
                            native.FileFlags = 0; native.ReportedSize = GeneratedFixture.Maximum + 1;
                            Reject(delegate { PublicTransfers.Execute(request, prepared, native, OperationReport.New(request)); }, "transfer_source_refused"); Assert(native.Copies == copies);
                        }
                        string oldGuest = policy.Guest; policy.Guest = @"C:\other-public";
                        Reject(delegate { using (PublicTransfer.Prepare(target, policy, request)) { } }, "transfer_source_refused"); policy.Guest = oldGuest;
                        bool isolated = false; try { using (PublicTransfer.Prepare(Synthetic("OtherTarget", '3'), policy, request)) { } } catch (BrokerError) { isolated = true; }
                        Assert(isolated);
                        File.WriteAllBytes(source, new byte[32]);
                        Reject(delegate { using (PublicTransfer.Prepare(target, policy, request)) { } }, "guest_fixture_generated_refused");
                    });
                });
                Test("transfer source and destination local paths are pinned against root replacement and source hardlinks", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative native)
                    {
                        Target target = Synthetic("TEST-VM", '2'); VmrunRequest request = SampleCommand("CopyFileFromHostToGuest"); string source, id;
                        using (PublicTransfer prepared = PublicTransfer.Prepare(target, policy, request))
                        {
                            source = prepared.SourcePath; id = prepared.Id; bool pinned = false;
                            try { Directory.Move(policy.Host.Path, policy.Host.Path + "-moved"); } catch (IOException) { pinned = true; }
                            Assert(pinned);
                        }
                        string link = source + ".link"; MakeFixtureLink("/H", link, source);
                        try { Reject(delegate { using (PublicTransfer.Prepare(target, policy, VmrunRequest.Parse(new[] { "CopyFileFromGuestToHost", target.Name, "public", id, "32" }))) { } }, "export_path_redirected"); }
                        finally { File.Delete(link); }
                    });
                });
                Test("public transfer result schema refuses absent IDs oversized claims mixed helper results and fake native completions", delegate
                {
                    OperationReport report = OperationReport.New(SampleCommand("CopyFileFromHostToGuest"));
                    Reject(report.Validate, "worker_protocol_failed"); report.TransferId = new string('A', 32); report.TransferBytes = 32; report.Fixture = "public"; report.Completion = "public_transfer_roundtrip_verified"; report.Validate();
                    report.TransferBytes = GeneratedFixture.Maximum + 1; Reject(report.Validate, "worker_protocol_failed"); report.TransferBytes = 32;
                    report.FixtureGeneratedId = report.TransferId; report.FixtureGeneratedBytes = 32; Reject(report.Validate, "worker_protocol_failed");
                    Assert(ResultData.AllowedError("transfer_outcome_unknown") && Diagnostics.Name(Stage.TransferCopy) == "transfer_copy" && !Diagnostics.UserWait(Stage.TransferCopy));
                });
                Test("public-share setup creates only a NEW dedicated generated directory and never adopts an existing user root", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative unused)
                    {
                        PublicShare share = PublicShare.Create(policy.Host.Path, "synthetic"); share.Validate();
                        Assert(share.Root.Path != policy.Host.Path && Path.GetFileName(share.Root.Path) == "broker-share-" + share.Id);
                        using (share.Open()) { Assert(Directory.GetFiles(share.Root.Path).Length == 1 && new FileInfo(Path.Combine(share.Root.Path, "public.bin")).Length == 1024); }
                        var forged = new PublicShare { Name = share.Name, Id = share.Id, Root = policy.Host };
                        Reject(forged.Validate, "public_share_not_approved");
                        File.WriteAllText(Path.Combine(share.Root.Path, "foreign.txt"), "SYNTHETIC-PUBLIC");
                        Reject(delegate { using (share.Open()) { } }, "public_share_not_approved");
                    });
                });
                Test("native public-share flow adds readonly, updates writable or readonly, and enables ONLY the sole exact owned mapping", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative unused)
                    {
                        PublicShare share = PublicShare.Create(policy.Host.Path, "synthetic"); var native = new LocalShareNative();
                        foreach (VmrunRequest request in new[] { SampleCommand("addSharedFolder"), VmrunRequest.Parse(new[] { "setSharedFolderState", "TEST-VM", "synthetic", "writable" }), SampleCommand("setSharedFolderState"), SampleCommand("enableSharedFolders") })
                        {
                            var report = OperationReport.New(request); PublicSharing.Execute(request, share, native, report); report.Validate();
                            Assert(report.ShareName == share.Name && !new ResultData { Ok = true, Target = "TEST-VM", Operation = report }.Json().Contains(share.Root.Path));
                        }
                        Assert(native.MappingCount == 1 && native.Flags == 0 && native.Adds == 1 && native.Sets == 2 && native.Enables == 1);
                        Reject(delegate { PublicSharing.Execute(SampleCommand("addSharedFolder"), share, native, OperationReport.New(SampleCommand("addSharedFolder"))); }, "public_share_foreign_mapping");
                        Assert(native.Adds == 1);
                    });
                });
                Test("pre-existing or foreign shared folders cannot be enabled changed or replaced by the new public grant", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative unused)
                    {
                        PublicShare share = PublicShare.Create(policy.Host.Path, "synthetic");
                        foreach (string name in new[] { "addSharedFolder", "setSharedFolderState", "enableSharedFolders" })
                            foreach (int mappingCount in new[] { 1, 2, 17 })
                            {
                                var native = new LocalShareNative { MappingCount = mappingCount, Path = @"D:\SYNTHETIC-FOREIGN-USER-TREE", Name = "foreign" };
                                VmrunRequest request = SampleCommand(name);
                                Reject(delegate { PublicSharing.Execute(request, share, native, OperationReport.New(request)); }, "public_share_foreign_mapping");
                                Assert(native.Adds == 0 && native.Sets == 0 && native.Enables == 0);
                            }
                        var empty = new LocalShareNative(); VmrunRequest enable = SampleCommand("enableSharedFolders");
                        Reject(delegate { PublicSharing.Execute(enable, share, empty, OperationReport.New(enable)); }, "public_share_foreign_mapping"); Assert(empty.Enables == 0);
                    });
                });
                Test("public-share post-dispatch failures are unknown with no rollback or foreign-map repair", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative unused)
                    {
                        PublicShare share = PublicShare.Create(policy.Host.Path, "synthetic");
                        var native = new LocalShareNative { ReplaceAfterAdd = true }; VmrunRequest request = SampleCommand("addSharedFolder");
                        Reject(delegate { PublicSharing.Execute(request, share, native, OperationReport.New(request)); }, "public_share_outcome_unknown");
                        Assert(native.Adds == 1 && native.MappingCount == 2 && native.Sets == 0 && native.Enables == 0 && Directory.Exists(share.Root.Path));
                    });
                });
                Test("public sharing still requires separate policy, exact name, disposable and target isolation without credentials or approval callbacks", delegate
                {
                    foreach (string name in new[] { "addSharedFolder", "setSharedFolderState", "enableSharedFolders" })
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", name); runtime.Policies[runtime.Resolve("TEST-VM").Binding].Share = null;
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "public_share_not_approved"); Assert(runtime.Credential == null && !runtime.Events.Contains("connect"));
                        runtime = new FakeRuntime { Consent = false }; Grant(runtime, "TEST-VM", name);
                        Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand(name), runtime)).Ok && runtime.Credential == null && !runtime.Events.Contains("operation-consent"));
                        runtime = new FakeRuntime { RevokePolicyAtPrepare = true }; Grant(runtime, "TEST-VM", name);
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "capability_policy_changed"); Assert(!runtime.Events.Contains("operation:" + name));
                        runtime = new FakeRuntime(); Grant(runtime, "SAFE-DC", name); VmrunRequest protectedRequest = SampleCommand(name); protectedRequest.TargetName = "SAFE-DC";
                        Reject(delegate { CatalogEngine.Execute(protectedRequest, runtime); }, "protected_target_refused");
                    }
                    var wrong = new FakeRuntime(); Grant(wrong, "TEST-VM", "addSharedFolder"); VmrunRequest mismatch = VmrunRequest.Parse(new[] { "addSharedFolder", "TEST-VM", "other" });
                    Reject(delegate { CatalogEngine.Execute(mismatch, wrong); }, "public_share_not_approved");
                    var runtimeOnly = new FakeRuntime(); Grant(runtimeOnly, "TEST-VM", "enableSharedFolders");
                    Reject(delegate { CatalogEngine.Execute(VmrunRequest.Parse(new[] { "enableSharedFolders", "TEST-VM", "runtime" }), runtimeOnly); }, "unsupported_operation_option");
                });
                Test("public sharing refuses changed root identity modified fixture and real synthetic junction redirection", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot policy, LocalTransferNative unused)
                    {
                        PublicShare share = PublicShare.Create(policy.Host.Path, "synthetic"); string original = share.Root.Identity; share.Root.Identity = new string('0', 64);
                        Reject(delegate { using (share.Open()) { } }, "export_root_identity_changed"); share.Root.Identity = original;
                        string source = Path.Combine(share.Root.Path, "public.bin");
                        File.WriteAllBytes(source, new byte[1024]); Reject(delegate { using (share.Open()) { } }, "guest_fixture_generated_refused");
                        string other = share.Root.Path + "-original"; Directory.Move(share.Root.Path, other); MakeFixtureLink("/J", share.Root.Path, other);
                        try { Reject(delegate { using (share.Open()) { } }, "export_path_redirected"); }
                        finally { Directory.Delete(share.Root.Path); Directory.Move(other, share.Root.Path); }
                    });
                });
                Test("optional new-share policy roundtrips without altering registry-v2 key and result cannot claim guest exposure verification", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot root, LocalTransferNative unused)
                    {
                        Target target = Synthetic("TEST-VM", '2'); PublicShare share = PublicShare.Create(root.Host.Path, "synthetic");
                        WithRegistry(delegate (string path, RegistryStore store)
                        {
                            store.Add(target); CapabilityProfile policy = CapabilityProfile.Default(target); policy.Share = share; policy.Disposable = true; policy.Commands.Add("addSharedFolder"); store.WritePolicy(target, policy);
                            Assert(store.ReadPolicy(target).Share.Id == share.Id && store.Read().Resolve(target.Name).CredentialKey == target.CredentialKey);
                        });
                        OperationReport report = OperationReport.New(SampleCommand("addSharedFolder")); Reject(report.Validate, "worker_protocol_failed");
                        report.ShareName = share.Name; report.Completion = "public_share_mapping_verified"; report.Validate();
                        report.TransferId = share.Id; Reject(report.Validate, "worker_protocol_failed");
                    });
                });
                Test("public VIX transfer and sharing adapters preserve exact x86 pointer int and one-byte Bool declaration layouts", delegate
                {
                    Type vix = typeof(Vix); var privateType = System.Reflection.BindingFlags.NonPublic;
                    var copy = vix.GetNestedType("RunPointerFn", privateType).GetMethod("Invoke").GetParameters();
                    Assert(copy.Length == 7 && copy[0].ParameterType == typeof(int) && copy[1].ParameterType == typeof(IntPtr) && copy[2].ParameterType == typeof(IntPtr) && copy[3].ParameterType == typeof(int) && copy[4].ParameterType == typeof(int));
                    var enable = vix.GetNestedType("ShareEnableFn", privateType).GetMethod("Invoke").GetParameters();
                    Assert(enable.Length == 5 && enable[0].ParameterType == typeof(int) && enable[1].ParameterType == typeof(byte) && enable[2].ParameterType == typeof(int) && enable[3].ParameterType == typeof(IntPtr));
                    var write = vix.GetNestedType("ShareWriteFn", privateType).GetMethod("Invoke").GetParameters();
                    Assert(write.Length == 6 && write[1].ParameterType == typeof(IntPtr) && write[2].ParameterType == typeof(IntPtr) && write[3].ParameterType == typeof(int));
                    var path = vix.GetNestedType("GuestPathFn", privateType).GetMethod("Invoke").GetParameters();
                    Assert(path.Length == 4 && path[1].ParameterType == typeof(IntPtr));
                });
                Test("guest exit3018 selects observed INTEGER or INT64 width without truncating or fabricating zero", delegate
                {
                    Assert(GuestExitReader.Width(1) == 4 && GuestExitReader.Width(5) == 8);
                    foreach (int value in new[] { 0, 1, 7, -1, Int32.MinValue, Int32.MaxValue })
                        Assert(GuestExitReader.Read(1, delegate (IntPtr pointer) { Marshal.WriteInt32(pointer, value); }) == value);
                    foreach (long value in new[] { 0L, 1L, -1L, (long)Int32.MaxValue + 1, Int64.MinValue, Int64.MaxValue })
                        Assert(GuestExitReader.Read(5, delegate (IntPtr pointer) { Marshal.WriteInt64(pointer, value); }) == value);
                    Assert(GuestExitReader.Read(1, delegate { }) == -1 && GuestExitReader.Read(5, delegate { }) == -1);
                });
                Test("guest exit nonnumeric unknown or Bool types refuse before property output is read with fixed numeric diagnostics", delegate
                {
                    try
                    {
                        foreach (int actual in new[] { 0, 2, 3, 4, 6, -1, 99 })
                        {
                            bool read = false;
                            Reject(delegate { GuestExitReader.Read(actual, delegate { read = true; }); }, "vix_property_type_mismatch"); Assert(!read);
                            ResultData error = ResultData.Error("vix_property_type_mismatch", Stage.CatalogOperation);
                            ResultData copy = ResultData.Parse(error.Json());
                            Assert(copy.NativePropertyId == 3018 && copy.NativePropertyActualType == actual && copy.NativePropertyExpectedType == "1_or_5");
                        }
                    }
                    finally { Diagnostics.FailedProperty = Diagnostics.FailedActualType = null; Diagnostics.FailedExpectedType = null; Diagnostics.Failure = null; }
                });
                Test("actual-width helper missing status1 is not failure or fabricated existence and mutation status is still checked", delegate
                {
                    foreach (int actual in new[] { 1, 5 })
                    {
                        long missing = GuestExitReader.Read(actual, delegate (IntPtr pointer) { if (actual == 1) Marshal.WriteInt32(pointer, 1); else Marshal.WriteInt64(pointer, 1); });
                        OperationReport report = OperationReport.New(SampleCommand("fileExistsInGuest")); report.GuestExitPropertyType = actual; GuestFixture.Complete(report, "fixture", missing); report.Validate();
                        Assert(report.Exists == false && !report.GuestExit.HasValue && ResultData.Parse(new ResultData { Ok = true, Operation = report }.Json()).Operation.GuestExitPropertyType == actual);
                        var mutation = OperationReport.New(SampleCommand("CreateTempfileInGuest"));
                        Reject(delegate { GuestFixture.Complete(mutation, "fixture", missing); }, "guest_fixture_mutation_uncertain");
                    }
                });
                Test("program and script numeric exit semantics remain nonzero failures independently of native numeric width", delegate
                {
                    foreach (string name in new[] { "runProgramInGuest", "runScriptInGuest" })
                        foreach (int actual in new[] { 1, 5 })
                        {
                            var report = OperationReport.New(SampleCommand(name)); report.GuestExitPropertyType = actual;
                            report.GuestExit = GuestExitReader.Read(actual, delegate (IntPtr pointer) { if (actual == 1) Marshal.WriteInt32(pointer, 7); else Marshal.WriteInt64(pointer, 7); });
                            var failed = new ResultData { Ok = false, ErrorCode = "guest_program_failed", Operation = report }; failed.Validate(); Assert(ResultData.Parse(failed.Json()).Operation.GuestExit == 7);
                            report.GuestExitPropertyType = 3; Reject(report.Validate, "worker_protocol_failed");
                        }
                });
                Test("native-property diagnostic fields cannot add freeform text arbitrary property IDs or contradictory success", delegate
                {
                    var error = new ResultData { ErrorCode = "vix_property_type_mismatch", NativePropertyId = 3018, NativePropertyActualType = 2, NativePropertyExpectedType = "1_or_5" }; error.Validate();
                    error.NativePropertyId = 7001; Reject(error.Validate, "worker_protocol_failed"); error.NativePropertyId = 3018;
                    error.NativePropertyExpectedType = "SYNTHETIC-PRIVATE"; Reject(error.Validate, "worker_protocol_failed"); error.NativePropertyExpectedType = "1_or_5";
                    error.Ok = true; Reject(error.Validate, "worker_protocol_failed");
                });
                Test("parent-observed installed six-column host network schema validates every column but exports names and kinds only", delegate
                {
                    const string text = "Total host networks: 2\r\nINDEX  NAME         TYPE         DHCP         SUBNET           MASK\r\n1 vmnet1 hostOnly true 192.0.2.0 255.255.255.0\r\n8 vmnet8 nat true 198.51.100.0 255.255.255.0\r\n";
                    using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(text) })
                    {
                        OperationReport report = CliParsing.Parse(SampleCommand("listHostNetworks"), reply); report.Validate();
                        Assert(report.Count == 2 && report.Inventory[0].Name == "vmnet1" && report.Inventory[0].Kind == "host-only" && report.Inventory[1].Kind == "nat");
                        string json = new ResultData { Ok = true, Operation = report }.Json();
                        Assert(!json.Contains("192.0.2") && !json.Contains("198.51.100") && !json.Contains("255.255") && !json.Contains("DHCP") && !json.Contains("SUBNET"));
                    }
                    using (var empty = new CliReply { Output = Encoding.UTF8.GetBytes("Total host networks: 0\nINDEX NAME TYPE DHCP SUBNET MASK\n") }) Assert(CliParsing.Parse(SampleCommand("listHostNetworks"), empty).Count == 0);
                });
                Test("installed network parser refuses malformed header count index type DHCP subnet and mask instead of raw fallback", delegate
                {
                    const string valid = "Total host networks: 2\nINDEX NAME TYPE DHCP SUBNET MASK\n1 vmnet1 hostOnly true 192.0.2.0 255.255.255.0\n8 vmnet8 nat true 198.51.100.0 255.255.255.0\n";
                    foreach (string invalid in new[] {
                        valid.Replace("networks: 2", "networks: 1"), valid.Replace("networks: 2", "networks: 02"), valid.Replace("INDEX NAME", "NAME INDEX"),
                        valid.Replace("MASK\n", "MASK EXTRA\n"), valid.Replace("8 vmnet8", "1 vmnet8"), valid.Replace("8 vmnet8", "08 vmnet8"), valid.Replace("vmnet8", "vmnet1"),
                        valid.Replace("8 vmnet8", "-8 vmnet8"), valid.Replace("8 vmnet8", "+8 vmnet8"), valid.Replace("8 vmnet8", "2147483648 vmnet8"), valid.Replace("8 vmnet8", "index vmnet8"),
                        valid.Replace("hostOnly", "SYNTHETIC-PRIVATE"), valid.Replace("true", "enabled"), valid.Replace("192.0.2.0", "192.0.2.1"), valid.Replace("192.0.2.0", "192.000.2.0"),
                        valid.Replace("198.51.100.0", "198.51.100.999"), valid.Replace("255.255.255.0", "255.0.255.0"), valid.Replace("255.255.255.0", "::"), valid + "SYNTHETIC-PRIVATE\n"
                    }) using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(invalid) }) Reject(delegate { CliParsing.Parse(SampleCommand("listHostNetworks"), reply); }, "cli_output_unrecognized");
                });
                Test("installed network identifiers are unique bounded canonical integers independent of row order contiguity and names", delegate
                {
                    const string header = "Total host networks: 2\nINDEX NAME TYPE DHCP SUBNET MASK\n";
                    foreach (string rows in new[] {
                        "8 vmnet8 nat true 198.51.100.0 255.255.255.0\n1 vmnet1 hostOnly true 192.0.2.0 255.255.255.0\n",
                        "12 vmnet1 hostOnly true 192.0.2.0 255.255.255.0\n97 vmnet8 nat true 198.51.100.0 255.255.255.0\n",
                        "2147483647 vmnet1 hostOnly true 192.0.2.0 255.255.255.0\n0 vmnet8 nat true 198.51.100.0 255.255.255.0\n"
                    }) using (var reply = new CliReply { Output = Encoding.UTF8.GetBytes(header + rows) })
                    {
                        OperationReport report = CliParsing.Parse(SampleCommand("listHostNetworks"), reply); report.Validate();
                        Assert(report.Count == 2 && report.Inventory.Exists(delegate (InventoryRow row) { return row.Name == "vmnet1" && row.Kind == "host-only"; }) && report.Inventory.Exists(delegate (InventoryRow row) { return row.Name == "vmnet8" && row.Kind == "nat"; }));
                        string json = new ResultData { Ok = true, Operation = report }.Json(); Assert(!json.Contains("2147483647") && !json.Contains("198.51.100") && !json.Contains("192.0.2") && !json.Contains("DHCP"));
                    }
                });
                Test("host policy metadata is private bounded atomic and single-writer without accessing VM registry or credentials", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        using (store.Lock())
                        {
                            store.Write("forward.json", new ForwardSnapshot { Network = "vmnet8" });
                            Reject(delegate { using (store.Lock()) { } }, "host_policy_busy");
                        }
                        Assert(store.Read<ForwardSnapshot>("forward.json").Digest() == network.Read("vmnet8").Digest());
                        var fail = new HostMetadata(store.DirectoryPath, store.MachineBinding, delegate { throw new IOException("SYNTHETIC-PUBLISH"); });
                        bool refused = false; try { using (fail.Lock()) fail.Write("forward.json", new ForwardSnapshot { Network = "vmnet9" }); } catch (IOException) { refused = true; }
                        Assert(refused && store.Read<ForwardSnapshot>("forward.json").Network == "vmnet8" && Directory.GetFiles(store.DirectoryPath, "new-*").Length == 0);
                        Reject(delegate { store.Read<ForwardSnapshot>("..\\outside.json"); }, "host_policy_invalid");
                    });
                });
                Test("full clone creates fresh owned UUID and local flat or embedded-sparse backing manifests, never source paths", delegate
                {
                    foreach (bool sparse in new[] { false, true }) WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        Target source = Synthetic("TEST-VM", '2'); VmrunRequest request = SampleCommand("clone"); var native = new LocalCloneNative { Sparse = sparse };
                        OperationReport report = OperationReport.New(request); OwnedClones.Create(source, root.Host, request, store, native, report); report.Validate();
                        CloneRecord record = OwnedClones.Read(store, report.CloneId); Assert(native.Clones == 1 && record.State == "ready" && record.Uuid != source.Uuid && record.SourceBinding == source.Binding && record.Disks.Count == (sparse ? 1 : 2));
                        Assert(!new ResultData { Ok = true, Target = source.Name, Operation = report }.Json().Contains(root.Host.Path));
                        Reject(delegate { OwnedClones.Create(source, root.Host, request, store, native, OperationReport.New(request)); }, "transfer_destination_exists"); Assert(native.Clones == 1);
                    });
                });
                Test("nonsecret clone setup and registration preserve source credentials and grant deletion ONLY to its distinct new clone", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata host, LocalForwardNative network)
                    {
                        string sourcePath = Path.Combine(Path.GetDirectoryName(root.Host.Path), "guest", "source.vmx"); File.WriteAllText(sourcePath, "uuid.bios = \"" + new string('2', 32) + "\"\n");
                        Target source = VmIdentity.Capture("FixtureSource", sourcePath); string sourceKey = source.CredentialKey;
                        WithRegistry(delegate (string ignored, RegistryStore registry)
                        {
                            registry.Add(source); CapabilityProfile policy = CapabilityProfile.Default(source); policy.Disposable = true; registry.WritePolicy(source, policy);
                            Request setup = RequestFor("setup-clones", source.Name, root.Host.Path, "--expect-binding", source.Binding, "--json");
                            ResultData saved = NonsecretSetup.Execute(setup, registry, host, network); saved.Validate(); Assert(saved.SetupSaved == "clone_root");
                            var native = new LocalCloneNative(); VmrunRequest clone = VmrunRequest.Parse(new[] { "clone", source.Name, "full" }); var created = OperationReport.New(clone);
                            OwnedClones.Create(source, registry.ReadPolicy(source).CloneParent, clone, host, native, created);
                            var request = RequestFor("register-clone", source.Name, created.CloneId, "FixtureClone", "--json");
                            ResultData result = NonsecretSetup.Execute(request, registry, host, network); result.Validate();
                            Target target = registry.Read().Resolve("FixtureClone"); CapabilityProfile targetPolicy = registry.ReadPolicy(target);
                            Assert(result.SetupSaved == "clone_registered" && target.CredentialKey != sourceKey && registry.Read().Resolve(source.Name).CredentialKey == sourceKey && targetPolicy.Disposable && targetPolicy.OwnedCloneId == created.CloneId);
                            targetPolicy.Demand(target, VmrunRequest.Parse(new[] { "deleteVM", target.Name }));
                            Reject(delegate { registry.ReadPolicy(source).Demand(source, VmrunRequest.Parse(new[] { "deleteVM", source.Name })); }, "capability_not_granted");
                            OperationReport deleted = OperationReport.New(VmrunRequest.Parse(new[] { "deleteVM", target.Name })); OwnedClones.Delete(target, created.CloneId, host, native, deleted); deleted.Validate();
                            Assert(native.Deletes == 1 && !File.Exists(target.Vmx) && File.Exists(source.Vmx) && OwnedClones.Read(host, created.CloneId).State == "deleted");
                        });
                    });
                });
                Test("clone state protection rejects running source same UUID and unknown clone replay without deleting residues", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        Target source = Synthetic("TEST-VM", '2'); var native = new LocalCloneNative { PowerState = 8 }; VmrunRequest request = SampleCommand("clone");
                        Reject(delegate { OwnedClones.Create(source, root.Host, request, store, native, OperationReport.New(request)); }, "clone_power_state_refused"); Assert(native.Clones == 0);
                        native.PowerState = 2; native.Uuid = source.Uuid;
                        Reject(delegate { OwnedClones.Create(source, root.Host, request, store, native, OperationReport.New(request)); }, "owned_clone_outcome_unknown");
                        Assert(native.Clones == 1 && File.Exists(native.Destination) && OwnedClones.Read(store, request.GeneratedId).State == "copied" && OwnedClones.Read(store, request.GeneratedId).CopyProof == "native_job_success_v1");
                        Reject(delegate { OwnedClones.Create(source, root.Host, request, store, native, OperationReport.New(request)); }, "transfer_destination_exists"); Assert(native.Clones == 1);
                    });
                });
                Test("VMDK no-parent and extent grammar refuses shared parents absolute paths raw disk types and unknown extents", delegate
                {
                    const string valid = "# Disk DescriptorFile\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 1 FLAT \"disk-flat.vmdk\" 0\n";
                    Assert(CloneDisks.Extents(valid).Count == 1);
                    foreach (string bad in new[] { valid.Replace("ffffffff", "12345678"), valid + "parentCID=ffffffff\n", valid + "parentFileNameHint=\"source.vmdk\"\n", valid.Replace("disk-flat.vmdk", @"..\source.vmdk"), valid.Replace("disk-flat.vmdk", @"D:\source.vmdk"), valid.Replace("FLAT", "VMFSRDM"), valid.Replace("RW 1", "RDONLY 1"), valid.Replace("monolithicFlat", "fullDevice") })
                        Reject(delegate { CloneDisks.Extents(bad); }, "owned_clone_backing_refused");
                });
                Test("clone deletion refuses changed backing identity foreign host files source binding and live power before destructive dispatch", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        Target source = Synthetic("TEST-VM", '2'); VmrunRequest request = SampleCommand("clone"); var native = new LocalCloneNative(); var report = OperationReport.New(request); OwnedClones.Create(source, root.Host, request, store, native, report);
                        CloneRecord record = OwnedClones.Read(store, report.CloneId); Target target = VmIdentity.Capture("FixtureClone", record.Vmx); record.RegisteredBinding = target.Binding; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        string foreign = Path.Combine(record.Root.Path, "foreign.txt"); File.WriteAllText(foreign, "SYNTHETIC-FOREIGN-PUBLIC");
                        Reject(delegate { OwnedClones.Delete(target, record.Id, store, native, OperationReport.New(SampleCommand("deleteVM"))); }, "owned_clone_refused"); Assert(native.Deletes == 0); File.Delete(foreign);
                        native.PowerState = 8; Reject(delegate { OwnedClones.Delete(target, record.Id, store, native, OperationReport.New(SampleCommand("deleteVM"))); }, "clone_power_state_refused"); native.PowerState = 2;
                        string disk = Path.Combine(record.Root.Path, "disk-flat.vmdk"); File.WriteAllBytes(disk + ".new", new byte[512]); File.Replace(disk + ".new", disk, null);
                        Reject(delegate { OwnedClones.Delete(target, record.Id, store, native, OperationReport.New(SampleCommand("deleteVM"))); }, "owned_clone_backing_refused"); Assert(native.Deletes == 0 && File.Exists(target.Vmx));
                        Reject(delegate { OwnedClones.ValidateCurrent(record, source); }, "owned_clone_refused");
                    });
                });
                Test("clone delete intent is durable before dispatch and partial failure cannot replay or borrow ownership", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        var native = new LocalCloneNative(); VmrunRequest request = SampleCommand("clone"); var report = OperationReport.New(request); OwnedClones.Create(Synthetic("TEST-VM", '2'), root.Host, request, store, native, report);
                        CloneRecord record = OwnedClones.Read(store, report.CloneId); Target target = VmIdentity.Capture("FixtureClone", record.Vmx); record.RegisteredBinding = target.Binding; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        native.FailDelete = true;
                        Reject(delegate { OwnedClones.Delete(target, record.Id, store, native, OperationReport.New(SampleCommand("deleteVM"))); }, "owned_clone_outcome_unknown");
                        Assert(native.Deletes == 1 && OwnedClones.Read(store, record.Id).State == "deleting" && File.Exists(target.Vmx));
                        Reject(delegate { OwnedClones.Delete(target, record.Id, store, native, OperationReport.New(SampleCommand("deleteVM"))); }, "owned_clone_refused"); Assert(native.Deletes == 1);
                    });
                });
                Test("new clone operations require owned receipts and refuse protected VM without credentials or approval UI", delegate
                {
                    foreach (string name in new[] { "clone", "deleteVM" })
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", name); CapabilityProfile policy = runtime.Policies[runtime.Resolve("TEST-VM").Binding]; policy.CloneParent = null; policy.OwnedCloneId = null;
                        Reject(delegate { CatalogEngine.Execute(SampleCommand(name), runtime); }, "owned_clone_refused"); Assert(!runtime.Events.Contains("connect") && runtime.Credential == null);
                        runtime = new FakeRuntime(); Grant(runtime, "SAFE-DC", name); VmrunRequest request = SampleCommand(name); request.TargetName = "SAFE-DC";
                        // A clone-parent setting on protected source is itself invalid.
                        if (name == "clone") runtime.Policies[runtime.Resolve("SAFE-DC").Binding].CloneParent = null;
                        Reject(delegate { CatalogEngine.Execute(request, runtime); }, "protected_target_refused"); Assert(runtime.Credential == null);
                    }
                });
                Test("machine forwarding setup captures full original mapping semantics and exact owned add removal restores them", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        network.State.Rows.Add(new ForwardRow { Protocol = "udp", HostPort = 4000, GuestPort = 53, Address = "10.1.2.3", Description = "SYNTHETIC-ORIGINAL-DESCRIPTION" });
                        string original = network.State.Digest(); DateTime now = DateTime.UtcNow;
                        ForwardPolicy policy = OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, original, new string('A', 32), now);
                        var add = OperationReport.New(SampleCommand("setPortForwarding")); OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, add); add.Validate();
                        Assert(network.Adds == 1 && network.State.Rows.Count == 2 && store.Read<ForwardPolicy>("forward.json").State == "active" && policy.Original.Digest() == original);
                        var remove = OperationReport.New(SampleCommand("deletePortForwarding")); OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now.AddHours(1), remove); remove.Validate();
                        Assert(network.Removes == 1 && network.State.Digest() == original && store.Read<ForwardPolicy>("forward.json").State == "removed");
                        string json = new ResultData { Ok = true, Operation = remove }.Json(); Assert(!json.Contains("SYNTHETIC-ORIGINAL") && !json.Contains("10.1.2.3"));
                    });
                });
                Test("forwarding refuses existing port non-NAT busy listener wrong snapshot and unsupported scope without any writes", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        DateTime now = DateTime.UtcNow; string digest = network.State.Digest(); network.Nat = false;
                        Reject(delegate { OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, digest, new string('A', 32), now); }, "forward_scope_refused"); network.Nat = true; network.Free = false;
                        Reject(delegate { OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, digest, new string('A', 32), now); }, "forward_scope_refused"); network.Free = true;
                        Reject(delegate { OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, new string('0', 64), new string('A', 32), now); }, "forward_snapshot_changed");
                        network.State.Rows.Add(new ForwardRow { Protocol = "tcp", HostPort = 62001, GuestPort = 80, Address = "10.1.2.3", Description = "SYNTHETIC-FOREIGN" });
                        Reject(delegate { OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, network.State.Digest(), new string('A', 32), now); }, "forward_snapshot_changed");
                        Assert(network.Adds == 0 && network.Removes == 0);
                        foreach (string address in new[] { "127.0.0.1", "0.0.0.0", "192.0.2.1", "::1", "8.8.8.8" }) Reject(delegate { ForwardPolicy.PrivateAddress(address); }, "forward_policy_required");
                    });
                });
                Test("uncertain forwarding add keeps ownership and explicit cleanup removes only its verified rule without replaying add", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        DateTime now = DateTime.UtcNow; OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, network.State.Digest(), new string('A', 32), now);
                        network.FailAfterAdd = true;
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, OperationReport.New(SampleCommand("setPortForwarding"))); }, "forward_outcome_unknown");
                        Assert(network.Adds == 1 && store.Read<ForwardPolicy>("forward.json").State == "prepared");
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, OperationReport.New(SampleCommand("setPortForwarding"))); }, "forward_snapshot_changed");
                        OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now, OperationReport.New(SampleCommand("deletePortForwarding")));
                        Assert(network.Adds == 1 && network.Removes == 1 && network.State.Rows.Count == 0);
                    });
                });
                Test("uncertain forwarding removal can observe exact restoration but never issues a second delete or removes changed foreign state", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        DateTime now = DateTime.UtcNow; OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, network.State.Digest(), new string('A', 32), now);
                        OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, OperationReport.New(SampleCommand("setPortForwarding")));
                        network.State.Rows[0].Description = "SYNTHETIC-REPLACED";
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now, OperationReport.New(SampleCommand("deletePortForwarding"))); }, "forward_snapshot_changed"); Assert(network.Removes == 0);
                        network.State.Rows[0].Description = store.Read<ForwardPolicy>("forward.json").Owned.Description; network.FailAfterRemove = true;
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now, OperationReport.New(SampleCommand("deletePortForwarding"))); }, "forward_outcome_unknown");
                        OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now, OperationReport.New(SampleCommand("deletePortForwarding")));
                        Assert(network.Removes == 1 && store.Read<ForwardPolicy>("forward.json").State == "removed");
                    });
                });
                Test("forwarding exact machine tuple expiry and snapshot guard cannot be overridden by VM policy or setup reset", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        DateTime now = DateTime.UtcNow; ForwardPolicy policy = OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, network.State.Digest(), new string('A', 32), now);
                        var wrong = SampleCommand("setPortForwarding"); wrong.Arguments[3] = "10.20.30.41";
                        Reject(delegate { OwnedForwarding.Execute(wrong, store, network, now, OperationReport.New(wrong)); }, "forward_scope_refused");
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now.AddHours(1), OperationReport.New(SampleCommand("setPortForwarding"))); }, "forward_snapshot_changed");
                        var otherMachine = new HostMetadata(store.DirectoryPath, new string('F', 64), null);
                        Reject(delegate { OwnedForwarding.Execute(SampleCommand("setPortForwarding"), otherMachine, network, now, OperationReport.New(SampleCommand("setPortForwarding"))); }, "forward_policy_required");
                        OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, OperationReport.New(SampleCommand("setPortForwarding")));
                        Reject(delegate { OwnedForwarding.Configure(store, network, "vmnet8", 62002, "10.20.30.40", 443, network.State.Digest(), new string('B', 32), now); }, "forward_ownership_conflict");
                        Assert(policy.Owned.HostPort == 62001 && network.Adds == 1);
                    });
                });
                Test("forwarding canonical snapshot preserves descriptions internally and detects changed rows duplicates and malformed formats", delegate
                {
                    const string original = "Total port forwardings: 1\nProtocol HostPort GuestIP GuestPort Description\ntcp 4000 10.1.2.3 80 SYNTHETIC-ORIGINAL\n";
                    ForwardSnapshot first = ForwardSnapshot.Parse("vmnet8", original); Assert(first.Rows[0].Description == "SYNTHETIC-ORIGINAL");
                    Assert(first.Digest() != ForwardSnapshot.Parse("vmnet8", original.Replace("ORIGINAL", "CHANGED")).Digest());
                    Reject(delegate { ForwardSnapshot.Parse("vmnet8", original + "tcp 4000 10.1.2.3 80 duplicate\n"); }, "forward_snapshot_invalid");
                    Reject(delegate { ForwardSnapshot.Parse("vmnet8", "Protocol HostPort GuestIP GuestPort Description\n"); }, "forward_snapshot_invalid");
                    var add = VmrunRequest.Parse(new[] { "setPortForwarding", "vmnet8", "tcp", "62001", "10.20.30.40", "443", "broker-temporary-" + new string('A', 32) });
                    CliPlan plan = CliPlan.Build(add, null, null); Assert(!plan.ReadOutput && plan.Arguments.Length == 9 && Array.IndexOf(plan.Arguments, "-gp") < 0 && Array.IndexOf(plan.Arguments, "-gu") < 0);
                    Reject(delegate { VmrunRequest.Parse(new[] { "setPortForwarding", "vmnet8", "udp", "62001", "10.20.30.40", "443" }); }, "invalid_request");
                    Reject(delegate { VmrunRequest.Parse(new[] { "setPortForwarding", "vmnet8", "tcp", "443", "10.20.30.40", "443" }); }, "forward_policy_required");
                });
                Test("forwarding legacy evidence field preserves owner scope reference without asserting isolation or changing exact owned restoration", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        string evidence = new string('B', 32), before = network.State.Digest(); DateTime now = DateTime.UtcNow;
                        OwnedForwarding.Configure(store, network, "vmnet8", 62001, "10.20.30.40", 443, before, evidence, now);
                        ForwardPolicy saved = store.Read<ForwardPolicy>("forward.json"); Assert(saved.IsolationEvidence == evidence && saved.State == "configured" && network.Adds == 0);
                        var report = OperationReport.New(SampleCommand("setPortForwarding")); OwnedForwarding.Execute(SampleCommand("setPortForwarding"), store, network, now, report);
                        string human = Output.Human(new ResultData { Ok = true, Operation = report }).Replace("\r", "").Replace("\n", " ");
                        Assert(human.Contains("ALL host interfaces") && human.Contains("NOT proof of isolation") && human.Contains("no automatic expiry cleanup"));
                        OwnedForwarding.Execute(SampleCommand("deletePortForwarding"), store, network, now.AddSeconds(30), OperationReport.New(SampleCommand("deletePortForwarding")));
                        Assert(network.Adds == 1 && network.Removes == 1 && network.State.Digest() == before && store.Read<ForwardPolicy>("forward.json").IsolationEvidence == evidence);
                    });
                });
                Test("Photon canonical Broadcom endpoints alone create anonymous TLS12 nonredirecting requests without sending them", delegate
                {
                    Assert(PhotonDownload.DescriptorUrl == "https://packages.broadcom.com/photon/5.0/GA/ovf/photon-hw15-5.0-dde71ec57.x86_64/photon-hw15-5.0-dde71ec57.x86_64.ovf");
                    Assert(PhotonDownload.ImageUrl == "https://packages.broadcom.com/photon/5.0/GA/ova/photon-hw15-5.0-dde71ec57.x86_64.ova");
                    Assert(PhotonDownload.LicenseHash == "8972C350E94198319988545474177DD5074052D91F5E35B86E5928D6471948AF" && PhotonDownload.ImageSha512 == "6BD6A307745ADB00B8452013F2C308C9ABEFD24A9D82611E8A1551AFB965873388EBDE81A34296DC0AD2FA7F0F7B4CD3924701ABDE0C963EA40B363C444BB037");
                    foreach (string url in new[] { PhotonDownload.DescriptorUrl, PhotonDownload.ImageUrl })
                    {
                        var request = OfficialPhotonSource.CreateRequest(url);
                        Assert(request.RequestUri.AbsoluteUri == url && request.Method == "GET" && !request.AllowAutoRedirect && request.Proxy == null && !request.UseDefaultCredentials && request.Credentials == null && request.CookieContainer == null && !request.PreAuthenticate && request.ServerCertificateValidationCallback == null && request.Headers["Authorization"] == null);
                        Assert(request.Timeout == 20000 && request.ReadWriteTimeout == 20000 && request.AutomaticDecompression == System.Net.DecompressionMethods.None && System.Net.ServicePointManager.SecurityProtocol == System.Net.SecurityProtocolType.Tls12);
                        request.Abort(); // No GetResponse/GetRequestStream: no request or binary fetch.
                    }
                });
                Test("Photon rejects every redirect non200 response changed endpoint and nonallowlisted URL before transport", delegate
                {
                    string url = PhotonDownload.DescriptorUrl;
                    foreach (string invalid in new[] { url.Replace("https:", "http:"), url.Replace("packages.broadcom.com", "packages.vmware.com"), url.Replace("packages.broadcom.com", "outside.invalid"), url + "?token=public", url + "#fragment", url.Replace("https://", "https://public@"), url.Replace("5.0/GA", "6.0/GA"), "https://packages.broadcom.com/", "https://packages.broadcom.com.evil.invalid/", null })
                        Reject(delegate { OfficialPhotonSource.CreateRequest(invalid); }, "photon_source_refused");
                    foreach (int status in new[] { 201, 206, 301, 302, 303, 307, 308, 401, 403, 404, 500 })
                        Reject(delegate { OfficialPhotonSource.DemandResponse(url, (System.Net.HttpStatusCode)status, new Uri(url)); }, "photon_source_refused");
                    Reject(delegate { OfficialPhotonSource.DemandResponse(url, System.Net.HttpStatusCode.OK, new Uri(PhotonDownload.ImageUrl)); }, "photon_source_refused");
                    Reject(delegate { OfficialPhotonSource.DemandResponse(url, System.Net.HttpStatusCode.OK, null); }, "photon_source_refused");
                    OfficialPhotonSource.DemandResponse(url, System.Net.HttpStatusCode.OK, new Uri(url));
                });
                Test("Photon descriptor redirect refusal preserves exact source error before creating scratch child or opening image", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        NonsecretSetup.Execute(RequestFor("setup-photon", root.Host.Path, "--existing-license-evidence", new string('A', 32), "--license-sha256", PhotonDownload.LicenseHash), null, store, network);
                        var source = new LocalPhotonSource { RedirectDescriptor = true };
                        Reject(delegate { PhotonDownload.Execute(store, source, OperationReport.New(SampleCommand("downloadPhotonVM"))); }, "photon_source_refused");
                        Assert(source.LicenseReads == 1 && source.ImageReads == 0 && Directory.GetDirectories(root.Host.Path).Length == 0);
                    });
                });
                Test("Photon configured root without existing applicable license evidence refuses before descriptor or image network access", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        ResultData setup = NonsecretSetup.Execute(RequestFor("setup-photon", root.Host.Path, "--json"), null, store, network); setup.Validate(); var source = new LocalPhotonSource();
                        Reject(delegate { PhotonDownload.Execute(store, source, OperationReport.New(SampleCommand("downloadPhotonVM"))); }, "photon_existing_license_required");
                        Assert(source.LicenseReads == 0 && source.ImageReads == 0 && Directory.GetDirectories(root.Host.Path).Length == 0);
                        Reject(delegate { RequestFor("setup-photon", root.Host.Path, "--accept-eula"); }, "invalid_request");
                    });
                });
                Test("Photon prior exact-terms evidence does not silently accept changed terms and a changed license blocks image fetch", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        ResultData setup = NonsecretSetup.Execute(RequestFor("setup-photon", root.Host.Path, "--existing-license-evidence", new string('A', 32), "--license-sha256", PhotonDownload.LicenseHash), null, store, network); setup.Validate();
                        var source = new LocalPhotonSource { License = new string('0', 64) };
                        Reject(delegate { PhotonDownload.Execute(store, source, OperationReport.New(SampleCommand("downloadPhotonVM"))); }, "photon_license_changed"); Assert(source.LicenseReads == 1 && source.ImageReads == 0);
                        Assert(new Uri(PhotonDownload.ImageUrl).Scheme == "https" && new Uri(PhotonDownload.ImageUrl).Host == "packages.broadcom.com" && FixtureProtocol.Hex(PhotonDownload.ImageSha512, 128));
                        Reject(delegate { VmrunRequest.Parse(new[] { "downloadPhotonVM", "https://outside.invalid/image.ova" }); }, "invalid_request");
                    });
                });
                Test("Photon copy primitive streams actual synthetic bytes and verifies exact length SHA512 without overwrite or regeneration", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot root, LocalTransferNative unused)
                    {
                        byte[] bytes = Encoding.ASCII.GetBytes("BROKER-PUBLIC-PHOTON-STREAM"); string hash; using (var sha = System.Security.Cryptography.SHA512.Create()) hash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
                        string path = Path.Combine(root.Host.Path, "synthetic-image.bin");
                        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                        using (var input = new MemoryStream(bytes)) { Assert(PhotonDownload.CopyChecked(input, file, bytes.Length, 1024, hash) == bytes.Length); file.Position = 0; Assert(file.ReadByte() == 'B'); }
                        foreach (int length in new[] { bytes.Length - 1, bytes.Length + 1 })
                        {
                            string test = Path.Combine(root.Host.Path, "size-" + length);
                            using (var file = new FileStream(test, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                            using (var input = new MemoryStream(bytes)) Reject(delegate { PhotonDownload.CopyChecked(input, file, length, 1024, hash); }, length < bytes.Length ? "photon_size_refused" : "photon_integrity_failed");
                        }
                        using (var file = new FileStream(Path.Combine(root.Host.Path, "tampered.bin"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                        using (var input = new MemoryStream(bytes)) Reject(delegate { PhotonDownload.CopyChecked(input, file, bytes.Length, 1024, new string('0', 128)); }, "photon_integrity_failed");
                    });
                });
                Test("Photon post-fetch size refusal leaves NEW private residue and cannot report a successful image", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative network)
                    {
                        NonsecretSetup.Execute(RequestFor("setup-photon", root.Host.Path, "--existing-license-evidence", new string('A', 32), "--license-sha256", PhotonDownload.LicenseHash), null, store, network);
                        var source = new LocalPhotonSource(); var result = OperationReport.New(SampleCommand("downloadPhotonVM"));
                        Reject(delegate { PhotonDownload.Execute(store, source, result); }, "photon_download_outcome_unknown");
                        Assert(source.ImageReads == 1 && result.PhotonId == null && Directory.GetDirectories(root.Host.Path).Length == 1);
                        HostPaths.CheckPrivateDirectory(Directory.GetDirectories(root.Host.Path)[0]);
                    });
                });
                Test("nonsecret setup grammar roundtrips without approval or password flags and clone native adapter is full0 delete2 only", delegate
                {
                    foreach (Request request in new[] { RequestFor("setup-clones", "TEST-VM", @"D:\SyntheticClones", "--expect-binding", new string('A', 64), "--json"), RequestFor("register-clone", "TEST-VM", new string('A', 32), "NewClone"), RequestFor("network-baseline", "vmnet8"), RequestFor("setup-forwarding", "vmnet8", "62001", "10.20.30.40", "443", new string('B', 64), new string('C', 32)), RequestFor("setup-photon", @"D:\SyntheticDownloads") })
                        Assert(Request.Parse(request.WorkerArguments()).Operation == request.Operation && request.SetupArguments != null);
                    Type clone = typeof(Vix).GetNestedType("CloneFn", System.Reflection.BindingFlags.NonPublic); var parameters = clone.GetMethod("Invoke").GetParameters();
                    Assert(parameters.Length == 8 && parameters[0].ParameterType == typeof(int) && parameters[1].ParameterType == typeof(int) && parameters[2].ParameterType == typeof(int) && parameters[3].ParameterType == typeof(IntPtr));
                    Assert(NativePlans.Symbol(SampleCommand("clone")) == "VixVM_Clone" && NativePlans.Symbol(SampleCommand("deleteVM")) == "VixVM_Delete");
                    var bad = OperationReport.New(SampleCommand("setPortForwarding")); Reject(bad.Validate, "worker_protocol_failed");
                    bad.MappingId = new string('A', 32); bad.Completion = "owned_forward_added"; bad.Validate();
                    var photon = OperationReport.New(SampleCommand("downloadPhotonVM")); photon.PhotonId = new string('A', 32); photon.DownloadBytes = PhotonDownload.Maximum + 1; photon.Completion = "official_photon_image_verified"; Reject(photon.Validate, "worker_protocol_failed");
                });
                Test("upgrade CLI validation releases BOTH actual synthetic VMX and directory pins before official writer with no native session", delegate
                {
                    WithTransferFixture(delegate (PublicTransferRoot root, LocalTransferNative unused)
                    {
                        string path = Path.Combine(root.Host.Path, "upgrade.vmx"), text = "uuid.bios = \"" + new string('7', 32) + "\"\n"; File.WriteAllText(path, text); Target target = VmIdentity.Capture("UpgradeFixture", path);
                        bool invoked = false;
                        OperationReport result = CliEngine.UpgradeWithoutPins(target, delegate
                        {
                            File.WriteAllText(path + ".new", text); File.Replace(path + ".new", path, null);
                            Directory.Move(root.Host.Path, root.Host.Path + "-move"); Directory.Move(root.Host.Path + "-move", root.Host.Path);
                            invoked = true; var report = OperationReport.New(SampleCommand("upgradevm")); report.Completion = "cli_completed_not_verified"; return report;
                        });
                        result.Validate(); Assert(invoked && result.Backend == "official-vmrun-cli");
                        CliPlan plan = CliPlan.Build(SampleCommand("upgradevm"), target, null); Assert(!plan.ReadOutput && String.Join(" ", plan.Arguments) == "-T ws upgradevm " + target.Vmx);
                    });
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "upgradevm"); ResultData observed = ResultData.Parse(CatalogEngine.Execute(SampleCommand("upgradevm"), runtime));
                    Assert(observed.Operation.Backend == "official-vmrun-cli" && !runtime.Events.Contains("connect") && !runtime.Events.Contains("open") && runtime.Credential == null);
                });
                Test("full clone associated NVRAM VMXF working and checkpoint references cannot retain a source or foreign host path", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        var native = new LocalCloneNative(); VmrunRequest request = SampleCommand("clone"); var report = OperationReport.New(request);
                        OwnedClones.Create(Synthetic("TEST-VM", '2'), root.Host, request, store, native, report); CloneRecord record = OwnedClones.Read(store, report.CloneId);
                        string original = File.ReadAllText(record.Vmx);
                        foreach (string field in new[] { "nvram = \"D:\\SyntheticSource\\source.nvram\"", "extendedConfigFile = \"..\\source.vmxf\"", "workingDir = \"D:\\SyntheticSource\"", "checkpoint.vmState = \"source.vmss\"" })
                        {
                            File.WriteAllText(record.Vmx, original + field + "\n"); Reject(delegate { CloneDisks.Inspect(record.Vmx); }, "owned_clone_backing_refused");
                        }
                        File.WriteAllText(record.Vmx, original + "nvram = \"machine.nvram\"\nextendedConfigFile = \"machine.vmxf\"\nworkingDir = \".\"\ncheckpoint.vmState = \"\"\n");
                        Assert(CloneDisks.Inspect(record.Vmx).Count == 2);
                        using (var file = File.OpenRead(record.Vmx)) Reject(delegate { DeviceBinding.Field(file, "RemoteDisplay.vnc.password", true); }, "device_not_approved");
                    });
                });
                Test("exact prior protocol4 image pins survive host-only fixes without expanding legacy3 rights or accepting unknown helpers", delegate
                {
                    foreach (string hash in new[] { "6EC73F9E903FF33F53E37CEB592EE174999B701F2B21E05A97E076E31EAB13F0", "0D2B91BAA4B953ACEABF21CE3A384BFCD4F17EC99CED6EF89D28CD932774191D", "3427B41616CC342A6E788ABE2CCF64FE228BD67887383D388136A45E433F530D", "95305E6C598796BD5B88C8621AA0FD8614F54C2FA8339186206D8A59BBE935A9", "F6E0EC1062D8B0A5FC7FF3ED6B8931A5B2031D2019EF86BB15B968BB39113D74", "80A4826BE193B71CF20D1E0A82BB8B6D860040BB828953EB4456F70E0C0C32CC", "1F2D9A04D7770E51B4D48FC4198FBCA193D273DBD0382A0F6A053E4463D0B16D", "E25F52F36F2DD43D1549135EEA521312ADC67A4792A234CBE6EE858ED1837669", "769878A1AE3ADA8964365AB53EF58E973187CCAB97169DF6EC495D5DD6FA44E4" })
                    {
                        var fixture = new GuestFixture { Alias = "fixture", EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = hash };
                        fixture.DemandImage(SampleCommand("deleteFileInGuest")); fixture.DemandImage(ApprovedRequest());
                        Assert(GuestFixture.SetupLine(fixture.PolicyLine(), new List<GuestFixture> { fixture }).ImageSha256 == hash);
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "deleteFileInGuest"); runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures = new List<GuestFixture> { fixture };
                        Reject(delegate { CatalogEngine.Execute(SampleCommand("deleteFileInGuest"), runtime); }, "guest_fixture_owned_refused"); Assert(runtime.Credential == null);
                        fixture.ImageSha256 = new string('0', 64); Reject(delegate { fixture.DemandImage(SampleCommand("deleteFileInGuest")); }, "guest_fixture_image_unavailable");
                    }
                });
                Test("completed native clone with deferred EMPTY BIOS identity gets fresh offline UUID without copying or booting again", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        var native = new LocalCloneNative { Uuid = "" }; var request = SampleCommand("clone"); var result = OperationReport.New(request); Target source = Synthetic("TEST-VM", '2');
                        OwnedClones.Create(source, root.Host, request, store, native, result); result.Validate(); CloneRecord record = OwnedClones.Read(store, result.CloneId);
                        Assert(record.State == "ready" && record.CopyProof == "native_job_success_v1" && record.Uuid != source.Uuid && Target.Hex(record.Uuid, 32) && native.Clones == 1 && native.Deletes == 0);
                        using (var file = File.OpenRead(record.Vmx)) Assert(VmIdentity.ReadUuid(file) == record.Uuid);
                        Assert(File.ReadAllText(record.Vmx).Contains("uuid.bios = \"" + CloneVmxIdentity.Format(record.Uuid) + "\""));
                    });
                });
                Test("a native copy failure remains PREPARED without a completion receipt even if partial files look plausible", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        var native = new LocalCloneNative { Uuid = "", FailClone = true }; var request = SampleCommand("clone");
                        Reject(delegate { OwnedClones.Create(Synthetic("TEST-VM", '2'), root.Host, request, store, native, OperationReport.New(request)); }, "owned_clone_outcome_unknown");
                        CloneRecord record = OwnedClones.Read(store, request.GeneratedId);
                        Assert(record.State == "prepared" && record.CopyProof == null && record.PlannedUuid == null && native.Clones == 1 && File.Exists(record.Vmx));
                    });
                });
                Test("withdrawn reviewed-case code is absent and even exact F200 metadata cannot supply a native completion receipt", delegate
                {
                    // String-only case metadata: NEVER opens the real VM path.
                    Assert(typeof(Program).Assembly.GetType("GuestBroker.ReviewedCloneRecovery") == null);
                    var record = new CloneRecord { Id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SourceBinding = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Root = new ExportRoot { Path = @"D:\SyntheticClones\clone-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, State = "prepared" };
                    Reject(record.DemandFinalizableCopy, "clone_copy_proof_required");
                    record.CopyProof = "reviewed_legacy_postcopy_v1"; record.State = "copied"; Reject(record.DemandFinalizableCopy, "clone_copy_proof_required");
                    record.State = "initializing"; Reject(record.DemandFinalizableCopy, "clone_copy_proof_required");
                    record.CopyProof = "native_job_success_v1"; record.DemandFinalizableCopy();
                });
                Test("prepared legacy clone cannot be finalized from file presence or an empty uuid alone", delegate
                {
                    foreach (string id in new[] { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", new string('A', 32) })
                        WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                        {
                            string before = FileSha(record.Vmx), journal = File.ReadAllText(Path.Combine(store.DirectoryPath, "clone-" + record.Id + ".json")); bool published = false;
                            Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, delegate { published = true; }); }, "clone_copy_proof_required");
                            Assert(FileSha(record.Vmx) == before && OwnedClones.Read(store, record.Id).State == "prepared");
                            Assert(!published && OwnedClones.Read(store, record.Id).CopyProof == null && File.ReadAllText(Path.Combine(store.DirectoryPath, "clone-" + record.Id + ".json")) == journal);
                        }, id);
                });
                Test("receipt-bound finalization changes ONLY uuid bytes and never reads or pins original source config or disk", delegate
                {
                    WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                    {
                        byte[] before = File.ReadAllBytes(record.Vmx); CloneUuidSlot slot;
                        using (var file = File.OpenRead(record.Vmx)) slot = CloneVmxIdentity.Slot(file);
                        record.State = "copied"; record.CopyProof = "native_job_success_v1"; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        CloneRecord ready;
                        using (var sourceConfig = new FileStream(source.Vmx, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        using (var sourceDisk = new FileStream(Path.Combine(Path.GetDirectoryName(source.Vmx), "source.vmdk"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                            ready = OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, AtomicClonePublish);
                        Assert(ready.State == "ready" && ready.CopyProof == "native_job_success_v1" && ready.Uuid != source.Uuid);
                        byte[] insertion = Encoding.ASCII.GetBytes(CloneVmxIdentity.Format(ready.Uuid)), after = File.ReadAllBytes(record.Vmx);
                        Assert(slot.Bytes == 0 && after.Length == before.Length + insertion.Length);
                        for (int i = 0; i < slot.Offset; i++) Assert(before[i] == after[i]);
                        for (int i = 0; i < insertion.Length; i++) Assert(after[slot.Offset + i] == insertion[i]);
                        for (long i = slot.Offset; i < before.Length; i++) Assert(before[i] == after[i + insertion.Length]);
                        Assert(FileSha(Path.Combine(Path.GetDirectoryName(source.Vmx), "source.vmdk")) == hash && File.Exists(source.Vmx));
                        string metadata = File.ReadAllText(Path.Combine(store.DirectoryPath, "clone-" + record.Id + ".json")); Assert(!metadata.Contains("SYNTHETIC-OPAQUE"));
                    });
                });
                Test("legacy reviewed proofs and assertion fields are rejected instead of silently becoming native completion", delegate
                {
                    WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                    {
                        record.CopyProof = "reviewed_legacy_postcopy_v1"; record.State = "copied";
                        Reject(delegate { record.Validate(store.MachineBinding); }, "owned_clone_refused");
                        record.CopyProof = "native_job_success_v1";
                        using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        string path = Path.Combine(store.DirectoryPath, "clone-" + record.Id + ".json"), valid = File.ReadAllText(path);
                        foreach (string field in new[] { "\"ReviewedSourceHash\":\"" + new string('A', 64) + "\"", "\"ReviewOriginBroker\":\"" + new string('B', 64) + "\"", "\"ReviewedSourceBytes\":35680813056" })
                        {
                            File.WriteAllText(path, valid.Insert(valid.LastIndexOf('}'), "," + field));
                            Reject(delegate { OwnedClones.Read(store, record.Id); }, "owned_clone_refused");
                        }
                        File.WriteAllText(path, valid); Assert(OwnedClones.Read(store, record.Id).CopyProof == "native_job_success_v1");
                        var result = new ResultData { Ok = true, SetupSaved = "clone_finalized", SetupId = record.Id, SetupProof = "reviewed_legacy_postcopy_v1" };
                        Reject(result.Validate, "worker_protocol_failed"); result.SetupProof = "native_job_success_v1"; result.Validate();
                    });
                });
                Test("finalization refuses registered foreign redirected or changed backing ownership before any identity rewrite", delegate
                {
                    WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                    {
                        Target registered = source.Clone(); registered.Name = "RegisteredClone"; registered.Vmx = record.Vmx;
                        record.State = "copied"; record.CopyProof = "native_job_success_v1"; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source, registered }, store, AtomicClonePublish); }, "owned_clone_refused");
                        string foreign = Path.Combine(record.Root.Path, "foreign.txt"); File.WriteAllText(foreign, "SYNTHETIC-PUBLIC");
                        Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, AtomicClonePublish); }, "clone_identity_outcome_unknown"); File.Delete(foreign);
                        CloneRecord other = OwnedClones.Read(store, record.Id); other.SourceBinding = new string('0', 64); using (store.Lock()) store.Write("clone-" + record.Id + ".json", other);
                        Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, AtomicClonePublish); }, "owned_clone_refused");
                        using (var vmx = File.OpenRead(record.Vmx)) Assert(CloneVmxIdentity.Slot(vmx).Uuid.Length == 0);
                    });
                });
                Test("UUID publication failure retains initializing proof and explicit finalize resumes metadata without replaying a copy", delegate
                {
                    WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                    {
                        // Synthetic receipt of a completed native call. The real
                        // creator writes this only after native Clone returns.
                        record.State = "copied"; record.CopyProof = "native_job_success_v1"; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        string before = FileSha(record.Vmx); int attempts = 0;
                        Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, delegate { attempts++; throw new IOException("synthetic publish failure"); }); }, "clone_identity_outcome_unknown");
                        CloneRecord pending = OwnedClones.Read(store, record.Id); Assert(pending.State == "initializing" && pending.CopyProof == "native_job_success_v1" && FileSha(record.Vmx) == before && attempts == 1);
                        CloneRecord ready = OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, AtomicClonePublish);
                        Assert(ready.State == "ready" && ready.Uuid == pending.PlannedUuid && Directory.GetFiles(record.Root.Path, "uuid-*.new").Length == 0);
                    });
                });
                Test("UUID publish succeeded but finalization interrupted is recoverable only through the durable exact after hash and planned UUID", delegate
                {
                    WithPreparedClone(delegate (PublicTransferRoot root, HostMetadata store, Target source, CloneRecord record, string hash, long bytes)
                    {
                        record.State = "copied"; record.CopyProof = "native_job_success_v1"; using (store.Lock()) store.Write("clone-" + record.Id + ".json", record);
                        Reject(delegate { OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, delegate (string temp, string destination) { AtomicClonePublish(temp, destination); throw new IOException("synthetic after-publication failure"); }); }, "clone_identity_outcome_unknown");
                        CloneRecord pending = OwnedClones.Read(store, record.Id);
                        using (var vmx = File.OpenRead(record.Vmx)) Assert(CloneVmxIdentity.Slot(vmx).Uuid == pending.PlannedUuid);
                        CloneRecord ready = OwnedClones.FinalizePrepared(source, root.Host, record.Id, new[] { source }, store, delegate { throw new Exception("publication must not repeat"); });
                        Assert(ready.State == "ready" && ready.Uuid == pending.PlannedUuid);
                    });
                });
                Test("UUID scanner rejects duplicate missing malformed and nonempty source values while finalizer grammar has no force flag", delegate
                {
                    WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
                    {
                        string path = Path.Combine(root.Host.Path, "probe.vmx");
                        foreach (string invalid in new[] { "nothing = \"public\"\n", "uuid.bios = \"\"\nuuid.bios = \"\"\n", "uuid.bios = \" \"\n", "uuid.bios = \"short\"\n", "uuid.bios = \"\" extra\n" })
                        { File.WriteAllText(path, invalid); using (var file = File.OpenRead(path)) Reject(delegate { CloneVmxIdentity.Slot(file); }, "clone_identity_refused"); }
                    });
                    Request request = RequestFor("finalize-clone", "TEST-VM", new string('A', 32), "--json");
                    Assert(Request.Parse(request.WorkerArguments()).SetupArguments.Length == 2);
                    Reject(delegate { RequestFor("finalize-clone", "TEST-VM", new string('A', 32), "--force-ready"); }, "invalid_request");
                    Reject(delegate { RequestFor("finalize-clone", "TEST-VM", new string('A', 32), "--source-disk-sha256", new string('B', 64), "--source-disk-bytes", "035680813056"); }, "invalid_request");
                });
                Test("Tools readiness waits only on on-not-paused unknown handles then reads actual same-handle state", delegate
                {
                    int reads = 0, waits = 0; bool waited;
                    int state = ToolsReadiness.Observe(0x0400 | 0x0008, delegate { reads++; return reads == 1 ? 1 : 2; }, delegate (int seconds) { Assert(seconds == 30); waits++; }, out waited);
                    Assert(state == 2 && waited && waits == 1 && reads == 2);
                    reads = waits = 0;
                    state = ToolsReadiness.Observe(0x0400 | 0x0008, delegate { reads++; return 1; }, delegate { waits++; }, out waited);
                    Assert(state == 1 && waited && waits == 1 && reads == 2); // Do not manufacture RUNNING2 after wait ACK.
                });
                Test("Tools readiness avoids paused off and already-running waits and preserves timeout failure without credentials", delegate
                {
                    foreach (int power in new[] { 2, 0x0008 | 0x0200, 32 })
                    { bool waited; Assert(ToolsReadiness.Observe(power, delegate { return 1; }, delegate { throw new Exception("must not wait"); }, out waited) == 1 && !waited); }
                    bool healthyWaited; Assert(ToolsReadiness.Observe(8, delegate { return 2; }, delegate { throw new Exception("already running"); }, out healthyWaited) == 2 && !healthyWaited);
                    int reads = 0;
                    Reject(delegate { bool ignored; ToolsReadiness.Observe(8, delegate { reads++; return 1; }, delegate { throw new BrokerError("vix_error_3000"); }, out ignored); }, "vix_error_3000"); Assert(reads == 1);
                    var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", "checkToolsState"); Assert(ResultData.Parse(CatalogEngine.Execute(SampleCommand("checkToolsState"), runtime)).Ok && runtime.Credential == null && !runtime.Events.Contains("login"));
                });
                Test("installTools selects only public MOUNT0 RETURN_IMMEDIATELY2 flags and reports mount ACK not installation", delegate
                {
                    Assert(ToolsReadiness.MountOnlyReturnImmediately == 2 && NativePlans.Flags(SampleCommand("installTools")) == 2 && (NativePlans.Flags(SampleCommand("installTools")) & 1) == 0);
                    var report = OperationReport.New(SampleCommand("installTools")); report.ToolsObservation = "mount_only_request_ack"; report.Validate();
                    string human = Output.Human(new ResultData { Ok = true, Operation = report }); Assert(human.Contains("AUTO_UPGRADE1 NOT used") && human.Contains("not completed Windows Tools installation"));
                    report.ToolsObservation = "installation_succeeded"; Reject(report.Validate, "worker_protocol_failed");
                    var other = OperationReport.New(SampleCommand("stop")); other.ToolsObservation = "mount_only_request_ack"; Reject(other.Validate, "worker_protocol_failed");
                });
                Test("only reserved PUBLIC launcher selects declared native interactive login8 and activate2 while keeping waiting and no guessed4", delegate
                {
                    VmrunRequest start = InteractiveFixtureRequest();
                    Assert(start.IsFixtureStart && start.NeedsCredential && NativePlans.LoginOptions(start) == 8 && NativePlans.Flags(start) == 2 && (NativePlans.Flags(start) & 1) == 0 && (NativePlans.Flags(start) & 4) == 0);
                    foreach (CatalogEntry entry in Catalog.Entries)
                    {
                        VmrunRequest request = SampleCommand(entry.Name); Assert(!request.IsFixtureStart && NativePlans.LoginOptions(request) == 0);
                        if (request.Entry.Name == "runProgramInGuest" || request.Entry.Name == "runScriptInGuest" || GuestFixture.Command(request.Entry.Name)) Assert(NativePlans.Flags(request) == 0);
                    }
                    Assert(NativePlans.LoginOptions(null) == 0 && GuestProcessSupervisor.LifetimeMilliseconds == 30000);
                    var loginAbi = typeof(Vix).GetNestedType("LoginFn", System.Reflection.BindingFlags.NonPublic).GetMethod("Invoke").GetParameters();
                    Assert(loginAbi.Length == 6 && loginAbi[0].ParameterType == typeof(int) && loginAbi[1].ParameterType == typeof(IntPtr) && loginAbi[2].ParameterType == typeof(IntPtr) && loginAbi[3].ParameterType == typeof(int));
                    var runtime = new FakeRuntime(); GrantInteractiveFixture(runtime);
                    ResultData result = ResultData.Parse(CatalogEngine.Execute(start, runtime));
                    Assert(result.Ok && runtime.LastLoginOptions == 8 && runtime.LastProgramOptions == 2 && result.Operation.FixtureLaunchMode == NativePlans.FixtureLaunchMode && result.Operation.GuestExit == null && result.Operation.FixtureProcessSlot == "slot3");
                    Assert(runtime.Events.IndexOf("prepare-operation") < runtime.Events.IndexOf("vault") && runtime.Events.IndexOf("vault") < runtime.Events.IndexOf("login") && !runtime.Events.Contains("operation-consent"));
                    string output = Output.Human(result).Replace("\r", "").Replace("\n", " "); Assert(output.Contains("NOT actual Session1") && output.Contains("waiting for checked launcher exit"));
                    result.Operation.FixtureLaunchMode = null; Reject(result.Operation.Validate, "worker_protocol_failed");
                    result.Operation.FixtureLaunchMode = "unproved_interactive4"; Reject(result.Operation.Validate, "worker_protocol_failed");
                    result.Operation.FixtureLaunchMode = NativePlans.FixtureLaunchMode; result.Operation.Validate();
                });
                Test("interactive fixture missing rights policy revocation wrong target and malformed shape stop before private credential access", delegate
                {
                    foreach (string missing in new[] { "command", "root", "process", "image" })
                    {
                        var runtime = new FakeRuntime(); GrantInteractiveFixture(runtime); CapabilityProfile profile = runtime.Policies[runtime.Resolve("TEST-VM").Binding];
                        if (missing == "command") profile.Commands.Remove("runProgramInGuest");
                        if (missing == "root") profile.GuestFixtures = null;
                        if (missing == "process") profile.GuestFixtures[0].OwnedProcesses = false;
                        if (missing == "image") profile.GuestFixtures[0].ImageSha256 = new string('0', 64);
                        string expected = missing == "command" ? "capability_not_granted" : missing == "root" ? "guest_fixture_not_approved" : missing == "process" ? "guest_fixture_process_refused" : "guest_fixture_image_unavailable";
                        Reject(delegate { CatalogEngine.Execute(InteractiveFixtureRequest(), runtime); }, expected);
                        Assert(runtime.Credential == null && !runtime.Events.Contains("connect") && !runtime.Events.Contains("login"));
                    }
                    var revoked = new FakeRuntime { RevokePolicyAtPrepare = true }; GrantInteractiveFixture(revoked);
                    Reject(delegate { CatalogEngine.Execute(InteractiveFixtureRequest(), revoked); }, "capability_policy_changed"); Assert(revoked.Credential == null && revoked.LastLoginOptions == null);
                    var wrong = new FakeRuntime { CrossCredential = true }; GrantInteractiveFixture(wrong); VmrunRequest request = InteractiveFixtureRequest(); request.TargetName = "SAFE-DC";
                    Reject(delegate { CatalogEngine.Execute(request, wrong); }, "protected_target_refused"); Assert(wrong.Credential == null);
                    var crossover = new FakeRuntime { CrossCredential = true }; GrantInteractiveFixture(crossover); Target alternate = Synthetic("LAB-ALT", '3'); crossover.Document.Targets.Add(alternate); Grant(crossover, alternate.Name, "runProgramInGuest");
                    crossover.Policies[alternate.Binding].GuestFixtures = crossover.Policies[crossover.Resolve("TEST-VM").Binding].GuestFixtures;
                    request = InteractiveFixtureRequest(); request.TargetName = alternate.Name;
                    Reject(delegate { CatalogEngine.Execute(request, crossover); }, "credential_target_mismatch"); Assert(crossover.LastLoginOptions == null && !crossover.Events.Contains("login") && crossover.Credential.Password.Pointer == IntPtr.Zero);
                    request = InteractiveFixtureRequest(); request.Arguments = new[] { "BROKER_PUBLIC_FIXTURE" };
                    Reject(delegate { NativePlans.LoginOptions(request); }, "invalid_request");
                    foreach (string flag in new[] { "-interactive", "-activeWindow", "-noWait" }) Reject(delegate { VmrunRequest.Parse(new[] { "runProgramInGuest", "TEST-VM", flag, "tool" }); }, "unsupported_operation_option");
                });
                Test("interactive login failure propagates exact native error with no fallback normal login or guest operation", delegate
                {
                    var runtime = new FakeRuntime { FailInteractiveLogin = true }; GrantInteractiveFixture(runtime);
                    Reject(delegate { CatalogEngine.Execute(InteractiveFixtureRequest(), runtime); }, "vix_error_3034");
                    Assert(runtime.LastLoginOptions == 8 && runtime.Events.FindAll(delegate (string name) { return name == "login"; }).Count == 1 && runtime.LastProgramOptions == null && !runtime.Events.Contains("operation:runProgramInGuest") && runtime.Credential.Password.Pointer == IntPtr.Zero);
                    Assert(Output.Human(ResultData.Error("vix_error_3035", Stage.GuestLoginWait)).Contains("No fallback login"));
                });
                Test("generic scripts programs identity and public fixture controls retain login0 and no activation permission or policy-key migration", delegate
                {
                    foreach (string name in new[] { "runProgramInGuest", "runScriptInGuest", "typeKeystrokesInGuest", "killProcessInGuest", "fileExistsInGuest" })
                    {
                        var runtime = new FakeRuntime(); Grant(runtime, "TEST-VM", name);
                        ResultData result = ResultData.Parse(CatalogEngine.Execute(SampleCommand(name), runtime)); Assert(result.Ok && runtime.LastLoginOptions == 0 && result.Operation.FixtureLaunchMode == null);
                        if (name != "runScriptInGuest") Assert(runtime.LastProgramOptions == 0);
                    }
                    var legacy = new FakeRuntime(); Assert(ResultData.Parse(Broker.Execute(RequestFor("identity", "TEST-VM", "--stored"), legacy)).Ok && legacy.LastLoginOptions == 0);
                    var scoped = new FakeRuntime(); GrantInteractiveFixture(scoped); Target target = scoped.Resolve("TEST-VM"); string key = target.CredentialKey, binding = target.Binding, fingerprint = scoped.Policies[target.Binding].Fingerprint();
                    Assert(ResultData.Parse(CatalogEngine.Execute(InteractiveFixtureRequest(), scoped)).Ok && scoped.Resolve("TEST-VM").CredentialKey == key && scoped.Resolve("TEST-VM").Binding == binding && scoped.Policies[target.Binding].Fingerprint() == fingerprint);
                });
                Test("interactive dot-local canonicalization uses only guest COMPUTERNAME and preserves exact private suffix and password buffer", delegate
                {
                    using (var user = SyntheticWide(@".\SYNTHETIC-User"))
                    using (var password = SyntheticWide("SYNTHETIC-password"))
                    using (var native = new SyntheticUsernameLogin(password))
                    using (var original = user.Utf8())
                    {
                        IntPtr passwordAddress = password.Pointer; byte[] before = SecretBytes(password);
                        GuestUsernameNormalization.Login(user, original, 8, native);
                        Assert(String.Join(",", native.Events) == "login0,computer,logout,revalidate,retain,login8");
                        Assert(native.UserPointers[0] == original.Pointer && native.UserPointers[1] != original.Pointer && native.Retained.Count == 1 && native.Retained[0].Pointer == native.UserPointers[1]);
                        Assert(native.UserTexts[0] == @".\SYNTHETIC-User" && native.UserTexts[1] == @"SYNTHETIC-GUEST\SYNTHETIC-User");
                        Assert(password.Pointer == passwordAddress && BytesEqual(before, SecretBytes(password)) && native.PasswordAddresses.Count == 2 && native.PasswordAddresses.TrueForAll(delegate (IntPtr p) { return p == passwordAddress; }));
                        Assert(GuestUsernameNormalization.Form == "dot_local_guest_sam");
                        using (var normalized = GuestUsernameNormalization.QualifyLocal(user, "SYNTHETIC-GUEST")) Assert(SyntheticWideText(normalized) == @"SYNTHETIC-GUEST\SYNTHETIC-User");
                        Assert(SyntheticWideText(user) == @".\SYNTHETIC-User");
                    }
                });
                Test("generic login0 never inspects or changes dot-local names and interactive bare SAM and UPN names remain byte-exact", delegate
                {
                    foreach (int mode in new[] { 0, 8 })
                        foreach (string name in new[] { @".\SYNTHETIC-User", "SYNTHETIC-User", @"SYNTHETIC-DOMAIN\SYNTHETIC-User", "SYNTHETIC-User@synthetic.invalid" })
                        {
                            if (mode == 8 && name.StartsWith(@".\", StringComparison.Ordinal)) continue;
                            GuestUsernameNormalization.Form = null;
                            using (var user = SyntheticWide(name))
                            using (var password = SyntheticWide("SYNTHETIC-password"))
                            using (var native = new SyntheticUsernameLogin(password))
                            using (var original = user.Utf8())
                            {
                                GuestUsernameNormalization.Login(user, original, mode, native);
                                Assert(String.Join(",", native.Events) == "login" + mode && native.UserPointers[0] == original.Pointer && native.UserTexts[0] == name && native.Retained.Count == 0);
                                Assert(mode == 0 ? GuestUsernameNormalization.Form == null : GuestUsernameNormalization.Form == (name.Contains("\\") ? "sam_qualified_unchanged" : name.Contains("@") ? "upn_unchanged" : "unqualified_unchanged"));
                            }
                        }
                });
                Test("interactive normalization preserves Unicode suffix bytes and refuses malformed dot-local forms before any native authentication", delegate
                {
                    using (var user = SyntheticWide(".\\SYNTHETIC-\u7528\u6237\u96EA"))
                    using (var normalized = GuestUsernameNormalization.QualifyLocal(user, "SYNTHETIC-GUEST"))
                        Assert(SyntheticWideText(normalized) == "SYNTHETIC-GUEST\\SYNTHETIC-\u7528\u6237\u96EA");
                    foreach (string invalid in new[] { @".\", @".\SYNTHETIC\other", @".\SYNTHETIC/other", @".\SYNTHETIC@invalid", ".\\SYNTHETIC\n" })
                        using (var user = SyntheticWide(invalid))
                        using (var password = SyntheticWide("SYNTHETIC-password"))
                        using (var native = new SyntheticUsernameLogin(password))
                        using (var original = user.Utf8())
                        {
                            Reject(delegate { GuestUsernameNormalization.Login(user, original, 8, native); }, "credential_format_rejected");
                            Assert(native.Events.Count == 0);
                        }
                });
                Test("interactive preflight authentication name-read logout and target-revalidation failures never reach login8 or a guest launcher", delegate
                {
                    foreach (string failure in new[] { "login0", "computer", "logout", "revalidate" })
                        using (var user = SyntheticWide(@".\SYNTHETIC-User"))
                        using (var password = SyntheticWide("SYNTHETIC-password"))
                        using (var native = new SyntheticUsernameLogin(password) { Failure = failure })
                        using (var original = user.Utf8())
                        {
                            Reject(delegate { GuestUsernameNormalization.Login(user, original, 8, native); }, "vix_error_3015");
                            Assert(!native.Events.Contains("login8") && native.Retained.Count == 0 && native.PasswordAddresses.Count == 1);
                            if (failure == "computer") Assert(native.Events.Contains("logout"));
                        }
                    foreach (string computer in new[] { "", "bad name", "bad\\name", new string('A', 64) })
                        using (var user = SyntheticWide(@".\SYNTHETIC-User"))
                        using (var password = SyntheticWide("SYNTHETIC-password"))
                        using (var native = new SyntheticUsernameLogin(password) { Computer = computer })
                        using (var original = user.Utf8())
                        {
                            Reject(delegate { GuestUsernameNormalization.Login(user, original, 8, native); }, "invalid_guest_identity");
                            Assert(native.Events.Contains("logout") && !native.Events.Contains("login8"));
                        }
                });
                Test("canonical interactive3035 remains exact after one planned original0 and one8 with no fallback or variant retry and buffers retained to teardown", delegate
                {
                    SecretBuffer retained;
                    using (var user = SyntheticWide(@".\SYNTHETIC-User"))
                    using (var password = SyntheticWide("SYNTHETIC-password"))
                    using (var native = new SyntheticUsernameLogin(password) { Failure = "login8" })
                    using (var original = user.Utf8())
                    {
                        Reject(delegate { GuestUsernameNormalization.Login(user, original, 8, native); }, "vix_error_3035");
                        Assert(String.Join(",", native.Events) == "login0,computer,logout,revalidate,retain,login8" && native.PasswordAddresses.Count == 2);
                        retained = native.Retained[0]; Assert(retained.Pointer != IntPtr.Zero && original.Pointer != IntPtr.Zero && password.Pointer != IntPtr.Zero);
                        string json = ResultData.Error("vix_error_3035", Stage.GuestLoginWait).Json();
                        Assert(ResultData.Parse(json).GuestUsernameForm == "dot_local_guest_sam" && !json.Contains("SYNTHETIC") && !json.Contains("password"));
                        string output = Output.Human(ResultData.Parse(json)).Replace("\r", "").Replace("\n", " "); Assert(output.Contains("NOT proof of a different account") && output.Contains("No fallback login"));
                    }
                    Assert(retained.Pointer == IntPtr.Zero);
                });
                Test("interactive diagnostic form accepts only fixed shape labels never arbitrary usernames SIDs paths or success-field injection", delegate
                {
                    foreach (string form in new[] { "dot_local_preflight", "dot_local_guest_sam", "unqualified_unchanged", "sam_qualified_unchanged", "upn_unchanged" })
                    {
                        var result = ResultData.Error("vix_error_3035", Stage.GuestLoginWait); result.GuestUsernameForm = form; Assert(ResultData.Parse(result.Json()).GuestUsernameForm == form);
                    }
                    foreach (string form in new[] { @"SYNTHETIC-DOMAIN\SYNTHETIC-User", "S-1-5-21-SYNTHETIC", @"C:\SYNTHETIC", "unknown" })
                    {
                        var result = ResultData.Error("vix_error_3035", Stage.GuestLoginWait); result.GuestUsernameForm = form; Reject(result.Validate, "worker_protocol_failed");
                    }
                    var success = new ResultData { Ok = true, Target = "TEST-VM", Computer = "SYNTHETIC-GUEST", Authentication = "succeeded", GuestUsernameForm = "sam_qualified_unchanged" }; Reject(success.Validate, "worker_protocol_failed");
                });
                Console.WriteLine("PASS " + count + " tests; no VMware calls, prompts, vault reads, or guest writes.");
                return 0;
            }
            catch (Exception error)
            {
                var known = error as BrokerError;
                Console.WriteLine("FAIL during test " + currentTest + " after " + count + " tests; type=" + error.GetType().Name + "; numeric=" + (error.HResult & 0xffff) + (known == null ? "" : "; code=" + known.Code) + " (raw diagnostics suppressed)");
                return 1;
            }
        }
        private static SupervisedResult Fixture(string name, int milliseconds = 3000)
        {
            return Supervisor.RunCore(typeof(Tests).Assembly.Location, new[] { name }, false, milliseconds);
        }
        private static string[] Prepend(string first, string[] rest) { var result = new List<string> { first }; result.AddRange(rest); return result.ToArray(); }
        private static void WithCodeFixture(Action<string, string> action)
        {
            string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "code-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            string path = Path.Combine(root, "fixture.ps1");
            try { action(root, path); }
            finally { if (File.Exists(path + ".new")) File.Delete(path + ".new"); if (File.Exists(path)) File.Delete(path); Directory.Delete(root); }
        }
        private static void WithGuestFixture(Action<string, GuestRootRecord> action)
        {
            string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "guest-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            try { action(root, GuestRootRecord.Capture(new string('A', 64), "fixture", root, new string('B', 64))); }
            finally
            {
                // Only these freshly owned fixture paths; no recursion or link walk.
                string nested = Path.Combine(root, "emptydir", "dest");
                if (Directory.Exists(nested)) { foreach (string file in Directory.GetFiles(nested)) File.Delete(file); Directory.Delete(nested); }
                string store = Path.Combine(root, "store");
                if (Directory.Exists(store)) { foreach (string file in Directory.GetFiles(store)) File.Delete(file); Directory.Delete(store); }
                foreach (string ownedDirectory in new[] { "dest", "emptydir", "owned-dir" })
                { string path = Path.Combine(root, ownedDirectory); if (Directory.Exists(path)) { foreach (string file in Directory.GetFiles(path)) File.Delete(file); Directory.Delete(path); } }
                foreach (string file in Directory.GetFiles(root)) File.Delete(file);
                Directory.Delete(root);
            }
        }
        private static void MakeFixtureLink(string flag, string link, string target)
        {
            var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"), "/d /c mklink " + flag + " " + WindowsArguments.Quote(link) + " " + WindowsArguments.Quote(target));
            start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            using (var process = System.Diagnostics.Process.Start(start)) { process.StandardOutput.ReadToEnd(); process.StandardError.ReadToEnd(); Assert(process.WaitForExit(5000) && process.ExitCode == 0); }
        }
        private static void WithOwnedFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        {
            WithGuestFixture(delegate (string root, GuestRootRecord record)
            { record.OwnedMutations = true; var store = new GuestRootStore(Path.Combine(root, "store")); store.Save(record); action(root, record, store); });
        }
        private static void WithRenameFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        {
            WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store)
            { record.OwnedRenames = true; store.Save(record); action(root, record, store); });
        }
        private static void WithDeleteFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        { WithOwnedFixture(delegate (string root, GuestRootRecord record, GuestRootStore store) { record.OwnedDeletes = true; store.Save(record); action(root, record, store); }); }
        private static void WithProcessFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        {
            WithGuestFixture(delegate (string root, GuestRootRecord record)
            {
                record.ImageSha256 = FixtureProtocol.ImageHash(typeof(Tests).Assembly.Location); record.OwnedProcesses = true;
                var store = new GuestRootStore(Path.Combine(root, "store")); store.Save(record);
                try { action(root, record, store); }
                finally
                {
                    foreach (string slot in new[] { "slot1", "slot2", "slot3", "slot4" }) if (store.ProcessExists(record, slot))
                    {
                        FixtureProcessRecord owned;
                        try { owned = store.ReadProcess(record, slot); } catch (FileNotFoundException) { continue; } // Normal asynchronous supervisor marker removal.
                        try { if (record.OwnedProcesses) GuestProcessSupervisor.Stop(store, record, slot); } catch (BrokerError) { }
                        IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, owned.Supervisor);
                        try { if (view != IntPtr.Zero) Native.WaitForSingleObject(view, 6500); } finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
                    }
                }
            });
        }
        private static void WithListingFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        {
            WithGuestFixture(delegate (string root, GuestRootRecord record)
            {
                record.PublicListing = true; var store = new GuestRootStore(Path.Combine(root, "store")); store.Save(record);
                string path = Path.Combine(root, "emptydir"); Directory.CreateDirectory(path); action(path, record, store);
            });
        }
        private static ApprovedListing ApprovedPlan()
        { return ApprovedListing.ParseLines(new[] { "emptydir|Alpha|a.txt|file", "emptydir|Beta|subdir|directory" }); }
        private static VmrunRequest ApprovedRequest()
        { return VmrunRequest.Parse(new[] { "listDirectoryInGuest", "TEST-VM", "fixture", "emptydir", "--approved", "--stored" }); }
        private static void GrantApproved(FakeRuntime runtime)
        {
            Grant(runtime, "TEST-VM", "listDirectoryInGuest"); GuestFixture fixture = runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures[0]; fixture.PublicListing = false; fixture.ApprovedListing = ApprovedPlan();
        }
        private static void WithApprovedFixture(Action<string, GuestRootRecord, GuestRootStore> action)
        {
            WithListingFixture(delegate (string path, GuestRootRecord record, GuestRootStore store)
            { record.PublicListing = false; record.ApprovedListing = ApprovedPlan(); store.Save(record); action(path, record, store); });
        }
        private static void WithListingBuffer(Action<IntPtr> action)
        {
            IntPtr pointer = Marshal.AllocHGlobal(GuestListing.BufferBytes);
            try { for (int i = 0; i < GuestListing.BufferBytes; i++) Marshal.WriteByte(pointer, i, 0); action(pointer); }
            finally { Marshal.FreeHGlobal(pointer); }
        }
        private static int DirectoryRecord(IntPtr buffer, int offset, string name, uint attributes, bool next)
        {
            int bytes = name.Length * 2, size = (GuestListing.NameOffset + bytes + 7) & ~7;
            Marshal.WriteInt32(buffer, offset, next ? size : 0); Marshal.WriteInt32(buffer, offset + 56, unchecked((int)attributes)); Marshal.WriteInt32(buffer, offset + 60, bytes);
            for (int i = 0; i < name.Length; i++) Marshal.WriteInt16(buffer, offset + GuestListing.NameOffset + i * 2, (short)name[i]); return size;
        }
        private static void Grant(FakeRuntime runtime, string name, string command)
        {
            Target target = runtime.Resolve(name); CapabilityProfile profile;
            if (!runtime.Policies.TryGetValue(target.Binding, out profile)) profile = CapabilityProfile.Default(target);
            profile.Disposable = true; profile.Revision = new string('A', 32); profile.Commands.Add(command);
            if (command == "runProgramInGuest") profile.Programs.Add(new ApprovedProgram { Alias = "tool", Path = @"C:\Windows\System32\whoami.exe" });
            if (command == "runScriptInGuest") profile.Scripts = new List<ApprovedScript> { new ApprovedScript { Alias = "script", Root = new ExportRoot { Path = @"D:\SyntheticCode", Identity = new string('1', 64) }, FileName = "fixture.ps1", FileIdentity = new string('2', 64), Sha256 = new string('3', 64), Interpreter = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" } };
            if (command == "removeSharedFolder") profile.RemovableShares = new List<string> { "synthetic" };
            if (command == "writeVariable") profile.PublicVariables = new List<PublicVariable> { new PublicVariable { Alias = "PUBLIC_TEST", Kind = "int32", Minimum = 0, Maximum = 100, Read = true, Write = true } };
            if (GuestFixture.Command(command)) profile.GuestFixtures = new List<GuestFixture> { new GuestFixture { Alias = "fixture", EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = HelperBuild.Hash, OwnedMutations = GuestOwned.Operation(GuestFixture.Operation(command)), PublicListing = GuestFixture.Listing(command), OwnedRenames = GuestFixture.Rename(command), OwnedDeletes = GuestFixture.Delete(command), OwnedProcesses = GuestFixture.ProcessStop(command) || GuestFixture.ProcessType(command), OwnedSink = GuestFixture.ProcessType(command) } };
            if (command == "captureScreen") profile.Export = new ExportRoot { Path = @"D:\SyntheticExports", Identity = new string('1', 64) };
            if (PublicTransfers.Command(command)) profile.Transfers = new List<PublicTransferRoot> { new PublicTransferRoot { Alias = "public", Host = new ExportRoot { Path = @"D:\SyntheticTransfers", Identity = new string('1', 64) }, Guest = @"C:\brokertest-transfer" } };
            if (PublicSharing.Command(command)) profile.Share = new PublicShare { Name = "synthetic", Id = new string('A', 32), Root = new ExportRoot { Path = @"D:\SyntheticShares\broker-share-" + new string('A', 32), Identity = new string('1', 64) } };
            if (command == "clone") profile.CloneParent = new ExportRoot { Path = @"D:\SyntheticClones", Identity = new string('1', 64) };
            if (command == "deleteVM") profile.OwnedCloneId = new string('A', 32);
            if (command == "connectNamedDevice" || command == "disconnectNamedDevice") profile.Devices = new List<ApprovedDevice> { new ApprovedDevice { Id = "sata0:1", Fingerprint = new string('A', 64), MediaIdentity = new string('B', 64), MediaPath = @"D:\SyntheticMedia\image.iso" } };
            runtime.Policies[target.Binding] = profile;
        }
        private static VmrunRequest InteractiveFixtureRequest()
        { return VmrunRequest.Parse(new[] { "runProgramInGuest", "TEST-VM", "BROKER_PUBLIC_FIXTURE", "--stored", "--", "fixture", "slot3" }); }
        private static void GrantInteractiveFixture(FakeRuntime runtime)
        {
            Grant(runtime, "TEST-VM", "runProgramInGuest");
            runtime.Policies[runtime.Resolve("TEST-VM").Binding].GuestFixtures = new List<GuestFixture> { new GuestFixture { Alias = "fixture", EnrollmentId = new string('A', 32), HelperPath = @"C:\BrokerTools\broker-guest-helper.exe", ImageSha256 = HelperBuild.Hash, OwnedProcesses = true, OwnedSink = true } };
        }
        // These managed conversions contain ONLY fixed synthetic test credentials.
        // Production normalization has no managed-string username getter.
        private static SecretBuffer SyntheticWide(string value)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value); var buffer = new SecretBuffer(bytes.Length + 2);
            Marshal.Copy(bytes, 0, buffer.Pointer, bytes.Length); return buffer;
        }
        private static string SyntheticWideText(SecretBuffer value) { return Marshal.PtrToStringUni(value.Pointer, value.WideLength()); }
        private static byte[] SecretBytes(SecretBuffer value) { var bytes = new byte[value.Size]; Marshal.Copy(value.Pointer, bytes, 0, bytes.Length); return bytes; }
        private static bool BytesEqual(byte[] first, byte[] second)
        {
            if (first.Length != second.Length) return false;
            for (int i = 0; i < first.Length; i++) if (first[i] != second[i]) return false;
            return true;
        }
        private sealed class SyntheticUsernameLogin : IGuestUsernameLogin, IDisposable
        {
            internal readonly List<string> Events = new List<string>(), UserTexts = new List<string>();
            internal readonly List<IntPtr> UserPointers = new List<IntPtr>(), PasswordAddresses = new List<IntPtr>();
            internal readonly List<SecretBuffer> Retained = new List<SecretBuffer>();
            private readonly SecretBuffer password;
            internal string Failure, Computer = "SYNTHETIC-GUEST";
            internal SyntheticUsernameLogin(SecretBuffer password) { this.password = password; }
            private void Event(string name) { Events.Add(name); if (Failure == name) throw new BrokerError(name == "login8" ? "vix_error_3035" : "vix_error_3015"); }
            public void Authenticate(SecretBuffer user, int options)
            {
                UserPointers.Add(user.Pointer); PasswordAddresses.Add(password.Pointer);
                int length = 0; while (Marshal.ReadByte(user.Pointer, length) != 0) length++;
                byte[] bytes = new byte[length]; Marshal.Copy(user.Pointer, bytes, 0, length); UserTexts.Add(Encoding.UTF8.GetString(bytes));
                Event("login" + options);
            }
            public string ComputerName() { Event("computer"); return Computer; }
            public void Logout() { Event("logout"); }
            public void Revalidate() { Event("revalidate"); }
            public void Retain(SecretBuffer user) { Event("retain"); Retained.Add(user); }
            public void Dispose() { foreach (SecretBuffer user in Retained) user.Dispose(); }
        }
        private static void DenyGrant(FakeRuntime runtime, string command)
        { runtime.Policies[runtime.Resolve("TEST-VM").Binding].Commands.Remove(command); }
        private static void GrantTimezone(FakeRuntime runtime)
        {
            Target target = runtime.Resolve("TEST-VM"); CapabilityProfile profile = CapabilityProfile.Default(target); profile.Disposable = true; profile.TimezoneMelbourne = true; runtime.Policies[target.Binding] = profile;
        }
        private static void WithVmxFixture(Action<string, string, Target> action)
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "known-vm-" + Guid.NewGuid().ToString("N") + ".vmx"), content = "uuid.bios = \"" + new string('3', 32) + "\"\nignored = \"SYNTHETIC-IGNORED\"\n";
            try { File.WriteAllText(path, content); action(path, content, VmIdentity.Capture("KnownFixture", path)); }
            finally { if (File.Exists(path + ".new")) File.Delete(path + ".new"); if (File.Exists(path)) File.Delete(path); }
        }
        private static VmrunRequest SampleCommand(string name)
        {
            bool host = name == "list" || name == "listHostNetworks" || name == "listPortForwardings" || name == "setPortForwarding" || name == "deletePortForwarding" || name == "downloadPhotonVM";
            var tokens = new List<string> { name }; if (!host) tokens.Add("TEST-VM");
            switch (name)
            {
                case "start": tokens.Add("nogui"); break;
                case "stop": case "reset": case "suspend": tokens.Add("soft"); break;
                case "snapshot": case "revertToSnapshot": case "deleteSnapshot": tokens.Add("synthetic snapshot"); break;
                case "listSnapshots": tokens.Add("showTree"); break;
                case "runProgramInGuest": tokens.AddRange(new[] { "tool", "--stored", "--", "two words", "Ω字", "literal&|<>" }); break;
                case "listProcessesInGuest": tokens.Add("--stored"); break;
                case "readVariable": tokens.AddRange(new[] { "guestEnv", "COMPUTERNAME", "--stored" }); break;
                case "writeVariable": tokens.AddRange(new[] { "guestVar", "PUBLIC_TEST", "3" }); break;
                case "fileExistsInGuest": case "directoryExistsInGuest": case "createDirectoryInGuest": case "CreateTempfileInGuest": case "listDirectoryInGuest": case "deleteDirectoryInGuest": case "deleteFileInGuest": tokens.AddRange(new[] { "fixture", "public.txt", "--stored" }); break;
                case "renameFileInGuest": tokens.AddRange(new[] { "fixture", "owned.txt", "renamed.txt", "--stored" }); break;
                case "CopyFileFromHostToGuest": tokens.AddRange(new[] { "public", "32", "--stored" }); break;
                case "CopyFileFromGuestToHost": tokens.AddRange(new[] { "public", new string('A', 32), "32", "--stored" }); break;
                case "setSharedFolderState": tokens.AddRange(new[] { "synthetic", "readonly" }); break;
                case "addSharedFolder": tokens.Add("synthetic"); break;
                case "removeSharedFolder": tokens.Add("synthetic"); break;
                case "killProcessInGuest": tokens.AddRange(new[] { "fixture", "slot1", "--stored" }); break;
                case "runScriptInGuest": tokens.AddRange(new[] { "script", "--stored" }); break;
                case "typeKeystrokesInGuest": tokens.AddRange(new[] { "fixture", "slot1", "PUBLIC_ALNUM", "--stored" }); break;
                case "connectNamedDevice": case "disconnectNamedDevice": tokens.Add("sata0:1"); break;
                case "getGuestIPAddress": tokens.Add("-wait"); break;
                case "listPortForwardings": tokens.Add("vmnet1"); break;
                case "setPortForwarding": tokens.AddRange(new[] { "vmnet8", "tcp", "62001", "10.20.30.40", "443" }); break;
                case "deletePortForwarding": tokens.AddRange(new[] { "vmnet8", "tcp", "62001" }); break;
                case "clone": tokens.Add("full"); break;
                case "downloadPhotonVM": tokens.Add("photon5"); break;
            }
            return VmrunRequest.Parse(tokens.ToArray());
        }
        private sealed class LocalTransferNative : IPublicTransferNative
        {
            internal string LocalRoot, GuestRoot;
            internal int Copies, RootFlags = 1, FileFlags;
            internal long? ReportedSize;
            internal bool TamperReceive, FailCopy;
            internal string PathFor(string path)
            {
                if (path == GuestRoot) return LocalRoot;
                Assert(path.StartsWith(GuestRoot + "\\broker-public-", StringComparison.Ordinal) && path.EndsWith(".bin", StringComparison.Ordinal));
                return Path.Combine(LocalRoot, Path.GetFileName(path));
            }
            public bool Exists(string path, bool directory) { return directory ? Directory.Exists(PathFor(path)) : File.Exists(PathFor(path)); }
            public void Info(string path, out long size, out int flags)
            {
                if (path == GuestRoot) { size = 0; flags = RootFlags; return; }
                size = ReportedSize ?? new FileInfo(PathFor(path)).Length; flags = FileFlags;
            }
            public void Copy(string source, string destination, bool toGuest)
            {
                Copies++; if (FailCopy) throw new BrokerError("vix_error_1");
                // Synthetic LOCAL byte copy between separate fixture directories,
                // not a VIX call. File.Copy(false) also exposes accidental reuse.
                File.Copy(toGuest ? source : PathFor(source), toGuest ? PathFor(destination) : destination, false);
                if (!toGuest && TamperReceive) using (var file = File.OpenWrite(destination)) file.WriteByte(0x7f);
            }
        }
        private sealed class LocalShareNative : IPublicShareNative
        {
            internal int MappingCount, Flags, Adds, Sets, Enables;
            internal string Name, Path;
            internal bool ReplaceAfterAdd;
            public int Count() { return MappingCount; }
            public bool Matches(PublicShare share, int flags) { return MappingCount == 1 && Name == share.Name && Path == share.Root.Path && Flags == flags; }
            public void Add(PublicShare share) { Adds++; MappingCount = ReplaceAfterAdd ? 2 : 1; Name = share.Name; Path = share.Root.Path; Flags = 0; }
            public void Set(PublicShare share, int flags) { Sets++; Assert(Name == share.Name && Path == share.Root.Path); Flags = flags; }
            public void Enable() { Enables++; }
        }
        private static void WithHostFixture(Action<PublicTransferRoot, HostMetadata, LocalForwardNative> action)
        {
            WithTransferFixture(delegate (PublicTransferRoot root, LocalTransferNative unused)
            { action(root, new HostMetadata(Path.Combine(Path.GetDirectoryName(root.Host.Path), "meta"), new string('9', 64), null), new LocalForwardNative()); });
        }
        private sealed class LocalCloneNative : ICloneNative
        {
            internal int PowerState = 2, Clones, Deletes;
            internal bool Sparse, FailDelete, FailClone;
            internal string Destination, Uuid = new string('3', 32);
            public int Power() { return PowerState; }
            public void Clone(string destination)
            {
                Clones++; Destination = destination; string root = Path.GetDirectoryName(destination);
                File.WriteAllText(destination, "uuid.bios = \"" + Uuid + "\"\nscsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"disk.vmdk\"\nsata0:1.deviceType = \"cdrom-image\"\nsata0:1.fileName = \"D:\\SyntheticNotOpened\\public.iso\"\nRemoteDisplay.vnc.password = \"SYNTHETIC-UNREAD\"\n");
                string descriptor = "# Disk DescriptorFile\nparentCID=ffffffff\ncreateType=\"" + (Sparse ? "monolithicSparse" : "monolithicFlat") + "\"\nRW 1 " + (Sparse ? "SPARSE \"disk.vmdk\"" : "FLAT \"disk-flat.vmdk\" 0") + "\n";
                if (Sparse)
                {
                    var bytes = new byte[1536]; Buffer.BlockCopy(BitConverter.GetBytes(0x564D444Bu), 0, bytes, 0, 4); Buffer.BlockCopy(BitConverter.GetBytes(1UL), 0, bytes, 28, 8); Buffer.BlockCopy(BitConverter.GetBytes(1UL), 0, bytes, 36, 8);
                    byte[] text = Encoding.UTF8.GetBytes(descriptor); Buffer.BlockCopy(text, 0, bytes, 512, text.Length); File.WriteAllBytes(Path.Combine(root, "disk.vmdk"), bytes);
                }
                else { File.WriteAllText(Path.Combine(root, "disk.vmdk"), descriptor); File.WriteAllBytes(Path.Combine(root, "disk-flat.vmdk"), new byte[512]); }
                if (FailClone) throw new IOException("synthetic incomplete native copy");
            }
            public void Delete()
            {
                Deletes++; if (FailDelete) throw new IOException("synthetic native deletion failure");
                foreach (string name in new[] { "machine.vmx", "disk.vmdk", "disk-flat.vmdk" }) { string path = Path.Combine(Path.GetDirectoryName(Destination), name); if (File.Exists(path)) File.Delete(path); }
            }
        }
        private static void AtomicClonePublish(string temp, string destination) { File.Replace(temp, destination, null); }
        private static string FileSha(string path)
        { using (var file = File.OpenRead(path)) using (var sha = System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", ""); }
        private static void WriteSparseFixture(string path, int grain, bool redundant)
        {
            const int sectors = 256; int overhead = grain, allocated = 2;
            byte[] bytes = new byte[(overhead + allocated * grain) * 512];
            Action<int, byte[]> set = delegate (int offset, byte[] value) { Buffer.BlockCopy(value, 0, bytes, offset, value.Length); };
            set(0, BitConverter.GetBytes(0x564D444Bu)); set(4, BitConverter.GetBytes(1u)); set(8, BitConverter.GetBytes(redundant ? 3u : 1u));
            set(12, BitConverter.GetBytes((ulong)sectors)); set(20, BitConverter.GetBytes((ulong)grain)); set(28, BitConverter.GetBytes(1UL)); set(36, BitConverter.GetBytes(1UL));
            set(44, BitConverter.GetBytes(512u)); set(48, BitConverter.GetBytes(redundant ? 7UL : 0UL)); set(56, BitConverter.GetBytes(2UL)); set(64, BitConverter.GetBytes((ulong)overhead));
            bytes[73] = 10; bytes[74] = 32; bytes[75] = 13; bytes[76] = 10;
            string descriptor = "# Disk DescriptorFile\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\nRW 256 SPARSE \"" + Path.GetFileName(path) + "\"\n";
            set(512, Encoding.ASCII.GetBytes(descriptor)); set(2 * 512, BitConverter.GetBytes(3u));
            if (redundant) set(7 * 512, BitConverter.GetBytes(8u));
            int physical = overhead;
            foreach (int logicalGrain in new[] { 0, sectors / grain - 1 })
            {
                set(3 * 512 + logicalGrain * 4, BitConverter.GetBytes((uint)physical)); if (redundant) set(8 * 512 + logicalGrain * 4, BitConverter.GetBytes((uint)physical));
                for (int sector = 0; sector < grain; sector++)
                {
                    int logical = logicalGrain * grain + sector;
                    if (logical < 8 || logical >= 248) for (int b = 0; b < 512; b++) bytes[(physical + sector) * 512 + b] = (byte)((logical * 13 + b * 7) & 255);
                }
                physical += grain;
            }
            File.WriteAllBytes(path, bytes);
        }
        private static void WithPreparedClone(Action<PublicTransferRoot, HostMetadata, Target, CloneRecord, string, long> action, string idOverride = null)
        {
            WithHostFixture(delegate (PublicTransferRoot root, HostMetadata store, LocalForwardNative unused)
            {
                string sourceVmx = Path.Combine(Path.GetDirectoryName(root.Host.Path), "guest", "source.vmx"), sourceDisk = Path.Combine(Path.GetDirectoryName(sourceVmx), "source.vmdk");
                File.WriteAllText(sourceVmx, "uuid.bios = \"" + new string('2', 32) + "\"\nscsi0:0.fileName = \"source.vmdk\"\n"); WriteSparseFixture(sourceDisk, 16, false);
                Target source = VmIdentity.Capture("FixtureSource", sourceVmx); string id = idOverride ?? Guid.NewGuid().ToString("N").ToUpperInvariant(), directory = Path.Combine(root.Host.Path, "clone-" + id); HostPaths.CreatePrivateDirectory(directory);
                var record = new CloneRecord { Machine = store.MachineBinding, Id = id, SourceBinding = source.Binding, SourceUuid = source.Uuid, State = "prepared", Root = ExportRoot.Capture(directory) };
                byte[] vmx = Encoding.ASCII.GetBytes("# PUBLIC PREFIX\r\n uuid.bios\t= \"\"\r\nscsi0:0.fileName = \"disk.vmdk\"\nRemoteDisplay.vnc.password = \"SYNTHETIC-OPAQUE-NOT-READ\"\r\n");
                File.WriteAllBytes(record.Vmx, vmx); WriteSparseFixture(Path.Combine(directory, "disk.vmdk"), 32, true);
                using (store.Lock()) store.Write("clone-" + id + ".json", record);
                action(root, store, source, record, FileSha(sourceDisk), new FileInfo(sourceDisk).Length);
            });
        }
        private sealed class LocalForwardNative : IForwardNative
        {
            internal bool Nat = true, Free = true, FailAfterAdd, FailAfterRemove;
            internal int Adds, Removes;
            internal ForwardSnapshot State = new ForwardSnapshot { Network = "vmnet8" };
            public bool IsNat(string network) { return Nat && network == "vmnet8"; }
            public bool PortFree(int port) { return Free && port >= 49152; }
            public ForwardSnapshot Read(string network)
            {
                Assert(network == State.Network); var result = new ForwardSnapshot { Network = State.Network };
                foreach (ForwardRow row in State.Rows) result.Rows.Add(new ForwardRow { Protocol = row.Protocol, HostPort = row.HostPort, GuestPort = row.GuestPort, Address = row.Address, Description = row.Description }); return result;
            }
            public void Add(string network, ForwardRow row)
            {
                Adds++; Assert(network == State.Network && !State.Rows.Exists(delegate (ForwardRow old) { return old.Key == row.Key; }));
                State.Rows.Add(new ForwardRow { Protocol = row.Protocol, HostPort = row.HostPort, GuestPort = row.GuestPort, Address = row.Address, Description = row.Description });
                if (FailAfterAdd) throw new IOException("synthetic after-add failure");
            }
            public void Remove(string network, ForwardRow row)
            { Removes++; Assert(network == State.Network && State.Rows.Exists(delegate (ForwardRow old) { return old.Canonical == row.Canonical; })); State.Rows.RemoveAll(delegate (ForwardRow old) { return old.Canonical == row.Canonical; }); if (FailAfterRemove) throw new IOException("synthetic after-remove failure"); }
        }
        private sealed class LocalPhotonSource : IPhotonSource
        {
            internal string License = PhotonDownload.LicenseHash;
            internal int LicenseReads, ImageReads;
            internal bool RedirectDescriptor;
            public string VerifyLicense() { LicenseReads++; if (RedirectDescriptor) OfficialPhotonSource.DemandResponse(PhotonDownload.DescriptorUrl, System.Net.HttpStatusCode.MovedPermanently, new Uri(PhotonDownload.DescriptorUrl)); return License; }
            public Stream OpenImage(out long length) { ImageReads++; length = 8; return new MemoryStream(Encoding.ASCII.GetBytes("SYNTHPUB")); }
        }
        private static void WithTransferFixture(Action<PublicTransferRoot, LocalTransferNative> action)
        {
            string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tf-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            if (!HostPaths.CreatePrivateDirectory(root)) throw new Exception("synthetic fixture collision");
            try
            {
                string host = Path.Combine(root, "host"), guest = Path.Combine(root, "guest"); HostPaths.CreatePrivateDirectory(host); HostPaths.CreatePrivateDirectory(guest);
                var policy = new PublicTransferRoot { Alias = "public", Host = ExportRoot.Capture(host), Guest = @"C:\brokertest-transfer" }; policy.Validate();
                action(policy, new LocalTransferNative { LocalRoot = guest, GuestRoot = policy.Guest });
            }
            finally { RemoveSyntheticTransferTree(root, 0); }
        }
        private static void RemoveSyntheticTransferTree(string path, int depth)
        {
            // Only the new test-owned root, bounded depth and no reparse traversal.
            Assert(depth <= 5 && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0);
            foreach (string child in Directory.GetDirectories(path)) RemoveSyntheticTransferTree(child, depth + 1);
            foreach (string file in Directory.GetFiles(path)) { Assert((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0); File.Delete(file); }
            Directory.Delete(path);
        }
        private static int SyntheticWorker(string[] args)
        {
            Native.SetErrorMode(0x0001 | 0x0002 | 0x8000);
            Supervisor.WatchParent(args[2]);
            using (var pipe = new System.IO.Pipes.AnonymousPipeClientStream(System.IO.Pipes.PipeDirection.Out, args[1]))
            using (var writer = new StreamWriter(pipe, new UTF8Encoding(false)))
            {
                writer.AutoFlush = true; writer.NewLine = "\n"; Diagnostics.Channel = writer;
                Diagnostics.At(Stage.Starting);
                string fixture = args[3];
                if (fixture == "fixture-arguments")
                {
                    if (args.Length != 10 || args[4] != "two words" || args[5] != "Ω字" || args[6] != "a\"b" || args[7] != "trail\\" || args[8] != "&|<>%^!" || args[9] != "") return 99;
                }
                if (fixture == "fixture-crash") { Diagnostics.At(Stage.GuestLogin); Native.TerminateProcess(new IntPtr(-1), 0xC0000005); }
                if (fixture == "fixture-timeout")
                {
                    Diagnostics.At(Stage.GuestLoginWait);
                    using (var deadline = new Deadline(100)) System.Threading.Thread.Sleep(20000);
                }
                if (fixture == "fixture-stall") { Diagnostics.At(Stage.NativeLoad); System.Threading.Thread.Sleep(20000); }
                if (fixture == "fixture-cli-timeout")
                {
                    Diagnostics.At(Stage.CliCall);
                    try { using (BoundedCli.Run(typeof(Tests).Assembly.Location, new[] { "--synthetic-cli", "stall" }, true, 150, 1024, null)) { } }
                    catch (BrokerError error)
                    {
                        var failed = ResultData.Error(error.Code, Stage.CliCall); failed.Outcome = "unknown";
                        Diagnostics.At(Stage.Complete); writer.WriteLine("R:" + failed.Json()); Diagnostics.Channel = null;
                        return error.Code == "official_cli_timeout" ? 124 : 3;
                    }
                    return 99;
                }
                if (fixture == "fixture-user-wait")
                {
                    using (var deadline = new Deadline(100))
                    using (deadline.Pause()) { Diagnostics.At(Stage.CredentialPrompt); System.Threading.Thread.Sleep(700); }
                    Diagnostics.At(Stage.CredentialPromptReturned);
                    writer.WriteLine("R:" + ResultData.Error("user_cancelled", Stage.CredentialPromptReturned).Json());
                    return 2;
                }
                if (fixture == "fixture-protocol") { writer.WriteLine("SYNTHETIC-OUTPUT-NOT-A-REAL-SECRET"); System.Threading.Thread.Sleep(20000); return 99; }
                Console.WriteLine("SYNTHETIC-OUTPUT-NOT-A-REAL-SECRET"); Console.Error.WriteLine("SYNTHETIC-OUTPUT-NOT-A-REAL-SECRET");
                Diagnostics.At(Stage.Complete);
                writer.WriteLine("R:{\"ok\":true,\"registration\":\"saved\"}");
                if (fixture == "fixture-late-crash") Native.TerminateProcess(new IntPtr(-1), 0xC0000005);
                Diagnostics.Channel = null;
                return 0;
            }
        }
        private static int SyntheticCli(string[] args)
        {
            Console.Error.WriteLine("SYNTHETIC-PRIVATE-STDERR");
            if (args[1] == "stall") { System.Threading.Thread.Sleep(20000); return 0; }
            if (args[1] == "flood") { Console.Write(new string('x', 40000)); return 0; }
            if (args[1] == "png")
            {
                byte[] png = new byte[128]; byte[] signature = { 137, 80, 78, 71, 13, 10, 26, 10 }; Array.Copy(signature, png, 8);
                png[11] = 13; png[12] = (byte)'I'; png[13] = (byte)'H'; png[14] = (byte)'D'; png[15] = (byte)'R'; png[19] = 1; png[23] = 1;
                using (var file = new FileStream(args[2], FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) file.Write(png, 0, png.Length);
                Console.WriteLine("SYNTHETIC-PRIVATE-STDOUT"); return 0;
            }
            Console.WriteLine("192.0.2.42"); return 0;
        }
    }
}
