using System;
using System.Threading;
using System.Collections.Generic;

namespace GuestBroker
{
    internal sealed class Deadline : IDisposable
    {
        private Timer timer;
        private readonly object gate = new object();
        private readonly int duration;
        private int generation;
        private bool disposed;
        internal Deadline() : this(45000) { }
        // Shorter durations are only used by the synthetic child-process test.
        internal Deadline(int milliseconds)
        {
            // Never FailFast or generate exception diagnostics/dumps on timeout.
            // A still-running native job may retain its input pointers: do not free
            // them and continue in a live process. Exit 124 means outcome UNKNOWN.
            if (milliseconds < 1 || milliseconds > 900000) throw new BrokerError("invalid_deadline");
            duration = milliseconds;
            Arm();
        }
        private void Arm()
        {
            lock (gate)
            {
                if (disposed) return;
                int token = ++generation;
                if (timer != null) timer.Dispose();
                timer = new Timer(delegate
                {
                    lock (gate) if (!disposed && generation == token) Native.TerminateProcess(new IntPtr(-1), 124);
                }, null, duration, Timeout.Infinite);
            }
        }
        internal IDisposable Pause()
        {
            lock (gate) { generation++; if (timer != null) { timer.Dispose(); timer = null; } }
            return new ResumeDeadline(this);
        }
        private sealed class ResumeDeadline : IDisposable
        {
            private Deadline owner;
            internal ResumeDeadline(Deadline value) { owner = value; }
            public void Dispose() { if (owner != null) { owner.Arm(); owner = null; } }
        }
        public void Dispose() { lock (gate) { disposed = true; generation++; if (timer != null) { timer.Dispose(); timer = null; } } }
    }

    internal interface IBrokerSession : IDisposable
    {
        int ApiVersion { get; }
        void OpenTarget(Target target);
        void Revalidate(Target target);
        IDisposable UserInteraction();
        string Status();
        void Login(GuestCredential credential);
        string Identity();
        void SetMelbourneTimezone();
        OperationReport ExecuteOperation(VmrunRequest request, CapabilityProfile profile);
        void PrepareOperation(VmrunRequest request);
        void PreparePrivateInputs(VmrunRequest request, CapabilityProfile profile);
    }

    internal interface IBrokerRuntime
    {
        IBrokerSession Connect();
        Target Resolve(string name);
        Target[] Registered();
        void Register();
        void Unregister(Target target);
        GuestCredential Acquire(Target target, bool stored, bool persist);
        void Save(Target target, GuestCredential credential);
        void Revoke(Target target);
    }

    internal interface IRegistrationMetadataRuntime { Target RefreshKnownVm(string name, string expectedBinding); }
    internal sealed class WindowsRuntime : IBrokerRuntime, ICatalogRuntime, IOfficialCliRuntime, IRegistrationMetadataRuntime, IHostOperationsRuntime, INonsecretSetupRuntime
    {
        private readonly RegistryStore registry = new RegistryStore();
        public IBrokerSession Connect() { return new Vix(); }
        public Target Resolve(string name) { Diagnostics.At(Stage.RegistryRead); return registry.Read().Resolve(name); }
        public Target[] Registered() { Diagnostics.At(Stage.RegistryRead); return registry.Read().Targets.ToArray(); }
        public void Register()
        {
            Diagnostics.At(Stage.RegistrationPrompt);
            Target target = RegistrationDialog.Choose();
            Diagnostics.At(Stage.RegistryWrite);
            using (var pinned = VmIdentity.Open(target)) { registry.Add(target); }
        }
        public void Unregister(Target target)
        {
            Diagnostics.At(Stage.RegistrationPrompt);
            if (Native.MessageBoxW(IntPtr.Zero, "Unregister " + target.Name + " at " + target.Vmx + " (UUID " + target.Uuid + ") and delete ONLY its broker credential? Other VMs are not affected.",
                "VMware Guest Broker: remove registration", 0x4 | 0x100 | 0x30 | 0x40000) != 6) throw new BrokerError("user_cancelled");
            Revoke(target);
            Diagnostics.At(Stage.RegistryWrite); registry.Remove(target);
        }
        private void AssertCurrent(Target target)
        {
            if (!target.SameRegistrationVersion(Resolve(target.Name))) throw new BrokerError("registration_changed");
        }
        public GuestCredential Acquire(Target target, bool stored, bool persist)
        {
            AssertCurrent(target);
            return stored ? GuestCredential.Read(target) : GuestCredential.Prompt(target, persist);
        }
        public void Save(Target target, GuestCredential credential) { AssertCurrent(target); Diagnostics.At(Stage.CredentialSave); credential.Save(target); }
        public Target RefreshKnownVm(string name, string expectedBinding) { Diagnostics.At(Stage.RegistryRead); Target current = registry.Read().Resolve(name); if (current.Binding != expectedBinding) throw new BrokerError("registration_changed"); Diagnostics.At(Stage.RegistryWrite); return registry.RefreshKnownVm(name, expectedBinding); }
        public void Revoke(Target target) { Diagnostics.At(Stage.CredentialDelete); GuestCredential.Revoke(target); }
        public CapabilityProfile Capabilities(Target target) { Diagnostics.At(Stage.CapabilityRead); return registry.ReadPolicy(target); }
        public OperationReport ExecuteOfficialCli(VmrunRequest request, Target target, CapabilityProfile profile) { return CliEngine.Real(request, target, profile); }
        public OperationReport ExecuteHostOperation(VmrunRequest request) { return HostOperations.Real(request); }
        public ResultData Setup(Request request) { return NonsecretSetup.Execute(request, registry, new HostMetadata(), new ForwardNative()); }
        public void ValidateTarget(Target target) { using (var proof = VmIdentity.Open(target)) { } }
        public void ConfigureCapabilities(Target target)
        {
            CapabilityProfile current = Capabilities(target);
            Diagnostics.At(Stage.CapabilityPrompt);
            CapabilityProfile edited = CapabilityDialog.Edit(target, current);
            Diagnostics.At(Stage.RegistryWrite); registry.WritePolicy(target, edited);
        }
    }

    internal static class Broker
    {
        internal static string Execute(Request request, IBrokerRuntime runtime)
        {
            if (request.SetupArguments != null)
            {
                var setup = runtime as INonsecretSetupRuntime; if (setup == null) throw new BrokerError("host_policy_invalid"); return setup.Setup(request).Json();
            }
            if (request.Operation == "catalog")
            {
                if (request.TargetName == null)
                {
                    var index = new List<CatalogIndexEntry>(); foreach (CatalogEntry entry in Catalog.Entries) index.Add(CatalogIndexEntry.From(entry));
                    return new ResultData { Ok = true, CatalogIndex = index }.Json();
                }
                return new ResultData { Ok = true, CatalogRows = new List<CatalogEntry> { Catalog.Find(request.TargetName) } }.Json();
            }
            if (request.Operation == "vmrun") return CatalogEngine.Execute(request.Vmrun, runtime);
            if (request.Operation == "rebind-knownvm")
            {
                var metadata = runtime as IRegistrationMetadataRuntime; if (metadata == null) throw new BrokerError("registration_refresh_unavailable");
                Target refreshed = metadata.RefreshKnownVm(request.TargetName, request.ExpectedBinding);
                return new ResultData { Ok = true, Target = refreshed.Name, IdentityBaseline = "path_uuid_v1", IdentityRevision = refreshed.IdentityRevision, RegistrationBinding = refreshed.Binding }.Json();
            }
            if (request.Operation == "policy")
            {
                Target approved = runtime.Resolve(request.TargetName);
                ((ICatalogRuntime)runtime).ConfigureCapabilities(approved);
                return new ResultData { Ok = true, Target = approved.Name, PolicySaved = "saved" }.Json();
            }
            if (request.Operation == "list")
            {
                var names = new System.Collections.Generic.List<string>();
                foreach (Target t in runtime.Registered()) { t.Validate(); names.Add("{\"name\":\"" + t.Name + "\",\"registered\":true}"); }
                return "{\"ok\":true,\"registeredVMs\":[" + String.Join(",", names) + "],\"guestAuthentication\":\"not_attempted\"}";
            }
            if (request.Operation == "register")
            {
                runtime.Register();
                return "{\"ok\":true,\"registration\":\"saved\"}";
            }
            Target target = request.Operation == "probe" ? null : runtime.Resolve(request.TargetName);
            if (target != null) Diagnostics.At(Stage.TargetResolved);
            if (request.Operation == "unregister")
            {
                runtime.Unregister(target);
                return "{\"ok\":true,\"target\":\"" + target.Name + "\",\"registration\":\"removed\"}";
            }
            // Revocation must work even if VMware was upgraded or removed.
            if (request.Operation == "revoke")
            {
                runtime.Revoke(target);
                return "{\"ok\":true,\"target\":\"" + target.Name + "\",\"credential\":\"revoked\"}";
            }
            if (request.Operation == "probe" || request.Operation == "status")
            {
                using (IBrokerSession session = runtime.Connect())
                {
                    if (request.Operation == "probe")
                        return "{\"ok\":true,\"nativeHostConnect\":true,\"architecture\":\"x86\",\"hostApiVersionProperty\":" + session.ApiVersion + ",\"guestAuthentication\":\"not_tested\"}";
                    session.OpenTarget(target);
                    return "{\"ok\":true,\"target\":\"" + target.Name + "\"," + session.Status() + ",\"guestAuthentication\":\"not_attempted\"}";
                }
            }
            // One native session per worker: do not unload/reload VIX around CredUI.
            // Keep credentials alive until native logout/teardown has completed.
            GuestCredential credential = null;
            VmAuthorization timezoneAuthorization = request.Operation == "timezone-melbourne" ? OperationAuthorization.ForTimezone(runtime, target) : null;
            try
            {
                string result;
                using (IBrokerSession session = runtime.Connect())
                {
                    session.OpenTarget(target);
                    if (timezoneAuthorization != null) timezoneAuthorization.Revalidate();
                    if (request.Stored) credential = runtime.Acquire(target, true, false);
                    else using (session.UserInteraction()) { credential = runtime.Acquire(target, false, request.Persist); }
                    if (credential.Binding != target.Binding) throw new BrokerError("credential_target_mismatch");
                    if (!target.SameRegistrationVersion(runtime.Resolve(target.Name))) throw new BrokerError("registration_changed");
                    if (timezoneAuthorization != null) timezoneAuthorization.Revalidate();
                    session.Revalidate(target);
                    session.Login(credential);
                    if (timezoneAuthorization != null) { timezoneAuthorization.Revalidate(); session.Revalidate(target); }
                    if (request.Operation == "enroll")
                        result = "{\"ok\":true,\"target\":\"" + target.Name + "\",\"credential\":\"" + (request.Persist ? "stored" : "validated_not_stored") + "\"}";
                    else if (request.Operation == "identity")
                    {
                        string hostname = Policy.SafeHostname(session.Identity());
                        result = "{\"ok\":true,\"target\":\"" + target.Name + "\",\"guestAuthentication\":\"succeeded\",\"toolsComputerName\":\"" + hostname + "\"}";
                    }
                    else
                    {
                        session.SetMelbourneTimezone();
                        result = "{\"ok\":true,\"target\":\"" + target.Name + "\",\"timezoneSetterExit\":0,\"timezoneReadback\":\"not_verified\"}";
                    }
                }
                // Validate login AND clean logout before committing enrollment.
                if (request.Operation == "enroll" && request.Persist) runtime.Save(target, credential);
                return result;
            }
            finally { if (credential != null) { Diagnostics.At(Stage.SecretCleanup); credential.Dispose(); } }
            // using/finally completes logout/native teardown BEFORE a result is emitted.
        }
    }

    internal static class Program
    {
        [STAThread]
        internal static int Main(string[] args)
        {
            bool json = Request.RequestedJson(args);
            try
            {
                if (args.Length >= 3 && args[0] == "--broker-worker") return Supervisor.WorkerMain(args);
                Request request = Request.Parse(args);
                if (request.Vmrun != null && !request.Vmrun.EnabledVariant) throw new BrokerError("catalog_operation_unavailable");
                Native.SetErrorMode(0x0001 | 0x0002 | 0x8000);
                if (request.Operation == "help" || request.Operation == "version")
                {
                    Console.WriteLine(Output.Wrap(request.Operation == "help" ? Output.Help : Output.Version));
                    return 0;
                }
                SupervisedResult result = Supervisor.Run(request);
                Output.Print(result.Result, request.Json);
                return result.ExitCode;
            }
            catch (BrokerError error)
            {
                Output.Print(ResultData.Error(error.Code, Diagnostics.Current), json);
                return 2;
            }
            catch (Exception)
            {
                // Never emit exception.Message, stack traces, arguments, user names,
                // library diagnostics, or raw guest output, even on unexpected errors.
                Output.Print(ResultData.Error("local_operation_failed", Diagnostics.Current), json);
                return 3;
            }
        }
    }
}
