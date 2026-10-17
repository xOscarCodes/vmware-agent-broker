using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GuestBroker
{
    internal sealed partial class Vix
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int Op4(int handle, int flags, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int Op5(int handle, int flags, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int InstallFn(int handle, int flags, IntPtr arguments, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong NumSnapshotsFn(int handle, out int number);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong SnapshotAtFn(int handle, int index, out int snapshot);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CreateSnapshotFn(int handle, IntPtr name, IntPtr description, int flags, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int RunPointerFn(int handle, IntPtr program, IntPtr arguments, int flags, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int RemoveSnapshotFn(int handle, int snapshot, int flags, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int RevertSnapshotFn(int handle, int snapshot, int flags, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NumResultsFn(int job, int property);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int PublicReadFn(int vm, int type, IntPtr key, int flags, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int PublicWriteFn(int vm, int type, IntPtr key, IntPtr value, int flags, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CloneFn(int vmHandle, int snapshot, int cloneType, IntPtr destination, int options, int properties, IntPtr callback, IntPtr data);
        private sealed class SnapshotItem { internal int Handle; internal string Reference; }
        private List<SnapshotItem> preparedSnapshots;
        private int preparedSnapshot;
        private PinnedScript preparedScript;
        private PublicTransfer preparedTransfer;
        private readonly List<SecretBuffer> operationText = new List<SecretBuffer>();
        private IntPtr RetainMetadataText(string text)
        {
            // Only declared non-secret labels/program/arguments use managed UTF-8.
            // Guest authentication never passes through this method. Retain the
            // native C string through complete native teardown, not P/Invoke return.
            var buffer = CopyNonSecretText(text);
            try { operationText.Add(buffer); return buffer.Pointer; }
            catch { buffer.Dispose(); throw; }
        }
        internal static SecretBuffer CopyNonSecretText(string text)
        {
            byte[] bytes = new UTF8Encoding(false, true).GetBytes(text);
            var buffer = new SecretBuffer(bytes.Length + 1);
            try { Marshal.Copy(bytes, 0, buffer.Pointer, bytes.Length); return buffer; }
            catch { buffer.Dispose(); throw; }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        public void PrepareOperation(VmrunRequest request)
        {
            if (operationPrepared || utf8User != null || loggedIn) throw new BrokerError("invalid_request");
            preparedLoginOptions = NativePlans.LoginOptions(request); operationPrepared = true;
            if (request.Entry.Name == "clone" || request.Entry.Name == "deleteVM") { deadline.Dispose(); deadline = new Deadline(900000); }
            if (request.Entry.Name != "deleteSnapshot" && request.Entry.Name != "revertToSnapshot") return;
            if (preparedSnapshots != null) throw new BrokerError("invalid_request");
            preparedSnapshots = Snapshots(); int matching = 0;
            foreach (SnapshotItem item in preparedSnapshots) if (SnapshotLabel(item.Handle) == request.Arguments[0]) { matching++; preparedSnapshot = item.Handle; }
            if (matching != 1) throw new BrokerError(matching == 0 ? "snapshot_not_found" : "snapshot_name_ambiguous");
            // Caller-owned native snapshot reference remains pinned across human
            // consent; never re-resolve a possibly replaced name afterwards.
        }
        public void PreparePrivateInputs(VmrunRequest request, CapabilityProfile profile)
        {
            if (PublicTransfers.Command(request.Entry.Name))
            {
                if (preparedTransfer != null) throw new BrokerError("invalid_request");
                preparedTransfer = PublicTransfer.Prepare(selected, profile.Transfer(request.Arguments[0]), request); return;
            }
            if (request.Entry.Name != "runScriptInGuest") return;
            Diagnostics.At(Stage.ScriptRead);
            if (preparedScript != null) throw new BrokerError("invalid_request");
            preparedScript = PinnedScript.Open(profile.Script(request.Arguments[0]), false);
        }

        public OperationReport ExecuteOperation(VmrunRequest request, CapabilityProfile profile)
        {
            if (selected == null) throw new BrokerError("native_target_mismatch");
            profile.Demand(selected, request);
            if (!operationPrepared || preparedLoginOptions != NativePlans.LoginOptions(request)) throw new BrokerError("invalid_request");
            if (request.NeedsCredential && !loggedIn) throw new BrokerError("credential_unavailable");
            Diagnostics.At(Stage.CatalogOperation);
            OperationReport result = OperationReport.New(request);
            string name = request.Entry.Name;
            string primary = NativePlans.Symbol(request);
            int flags = NativePlans.Flags(request);
            if (request.Entry.NeedsDisposable && vmxFile != null)
            {
                // VIX may replace VMX during host mutations. Identity was just
                // revalidated; do not deadlock its writer with our read pin.
                vmxFile.Dispose(); vmxFile = null;
            }
            switch (name)
            {
                case "start": EmptyJob(Function<Op5>(primary)(vm, flags, 0, IntPtr.Zero, IntPtr.Zero)); break;
                case "stop":
                case "reset":
                case "suspend":
                    EmptyJob(Function<Op4>(primary)(vm, flags, IntPtr.Zero, IntPtr.Zero)); break;
                case "pause": case "unpause": EmptyJob(Function<Op5>(primary)(vm, 0, 0, IntPtr.Zero, IntPtr.Zero)); break;
                case "installTools":
                    EmptyJob(Function<InstallFn>(primary)(vm, flags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)); result.ToolsObservation = "mount_only_request_ack"; break;
                case "snapshot":
                    int created = ResultHandle(Function<CreateSnapshotFn>(primary)(vm, RetainMetadataText(request.Arguments[0]), RetainMetadataText(""), 0, 0, IntPtr.Zero, IntPtr.Zero));
                    release(created); break;
                case "listSnapshots":
                    List<SnapshotItem> snapshots = Snapshots();
                    try
                    {
                        result.Count = snapshots.Count;
                        if (request.Arguments.Length != 0) { result.SnapshotRefs = new List<string>(); foreach (SnapshotItem item in snapshots) result.SnapshotRefs.Add(item.Reference); }
                    }
                    finally { foreach (SnapshotItem item in snapshots) release(item.Handle); }
                    break;
                case "deleteSnapshot":
                case "revertToSnapshot":
                    if (preparedSnapshot == 0) throw new BrokerError("snapshot_not_found");
                    if (name == "deleteSnapshot") EmptyJob(Function<RemoveSnapshotFn>(primary)(vm, preparedSnapshot, flags, IntPtr.Zero, IntPtr.Zero));
                    else EmptyJob(Function<RevertSnapshotFn>(primary)(vm, preparedSnapshot, 0, 0, IntPtr.Zero, IntPtr.Zero));
                    break;
                case "checkToolsState":
                    bool waited;
                    result.Tools = ToolsReadiness.Observe(IntProperty(vm, 129), delegate { return IntProperty(vm, 152); }, delegate (int seconds) { EmptyJob(Function<Op4>("VixVM_WaitForToolsInGuest")(vm, seconds, IntPtr.Zero, IntPtr.Zero)); }, out waited);
                    result.ToolsObservation = waited ? "same_handle_wait_completed" : "immediate_property"; break;
                case "readVariable":
                    if (!request.IsPublicVariable) { result.Computer = Identity(); break; }
                    PublicVariable readPolicy = profile.Variable(request.Arguments[1]);
                    int readJob = Function<PublicReadFn>(primary)(vm, 1, RetainMetadataText(readPolicy.NativeName), 0, IntPtr.Zero, IntPtr.Zero);
                    IntPtr scalar = IntPtr.Zero;
                    try
                    {
                        Complete(readJob); RequireType(readJob, 3056, 2); Success(getString(readJob, 3056, out scalar, 0));
                        PublicScalar value = PublicScalar.FromNative(scalar, readPolicy); readPolicy.Check(value);
                        result.SetPublic(readPolicy, value);
                    }
                    finally { if (scalar != IntPtr.Zero) free(scalar); if (readJob != 0) release(readJob); }
                    break;
                case "writeVariable":
                    PublicVariable writePolicy = profile.Variable(request.Arguments[1]); PublicScalar desired = PublicScalar.Parse(request.Arguments[2]); writePolicy.Check(desired);
                    EmptyJob(Function<PublicWriteFn>(primary)(vm, 1, RetainMetadataText(writePolicy.NativeName), RetainMetadataText(desired.Text), 0, IntPtr.Zero, IntPtr.Zero));
                    result.SetPublic(writePolicy, desired); // Request ack only, not readback.
                    break;
                case "listProcessesInGuest":
                    int job = Function<Op4>(primary)(vm, 0, IntPtr.Zero, IntPtr.Zero);
                    try
                    {
                        Complete(job); int count = Function<NumResultsFn>("VixJob_GetNumProperties")(job, 3051);
                        if (count < 0 || count > 256) throw new BrokerError("native_result_limit");
                        result.Count = count; // Never read owners, command lines or environment.
                    }
                    finally { if (job != 0) release(job); }
                    break;
                case "runProgramInGuest":
                    if (request.IsFixtureStart) { ExecuteFixture(request, profile, result); break; }
                    ApprovedProgram program = profile.Program(request.Arguments[0]);
                    var args = new ArraySegment<string>(request.Arguments, 1, request.Arguments.Length - 1);
                    int programJob = Function<RunPointerFn>(primary)(vm, RetainMetadataText(program.Path), RetainMetadataText(WindowsArguments.Join(args)), 0, 0, IntPtr.Zero, IntPtr.Zero);
                    try
                    {
                        Complete(programJob); int actualType;
                        result.GuestExit = ReadGuestExit(programJob, out actualType); result.GuestExitPropertyType = actualType;
                    }
                    finally { if (programJob != 0) release(programJob); }
                    // Native completion with an exit code is not a health/config assertion.
                    break;
                case "runScriptInGuest":
                    if (preparedScript == null) throw new BrokerError("script_not_approved");
                    ApprovedScript script = profile.Script(request.Arguments[0]);
                    // Honest PowerShell command-equivalent carrier: no vendor
                    // temp-script filename/extension/profile assumptions. Code
                    // stays in worker-owned native buffers, never host argv/IPC.
                    int scriptJob = Function<RunPointerFn>(primary)(vm, RetainMetadataText(script.Interpreter), preparedScript.Arguments, 0, 0, IntPtr.Zero, IntPtr.Zero);
                    try
                    {
                        Complete(scriptJob); int actualType;
                        result.GuestExit = ReadGuestExit(scriptJob, out actualType); result.GuestExitPropertyType = actualType;
                    }
                    finally { if (scriptJob != 0) release(scriptJob); }
                    break;
                case "CopyFileFromHostToGuest":
                case "CopyFileFromGuestToHost":
                    if (preparedTransfer == null) throw new BrokerError("transfer_not_approved");
                    PublicTransfers.Execute(request, preparedTransfer, new TransferNative(this), result); break;
                case "addSharedFolder":
                case "setSharedFolderState":
                case "enableSharedFolders":
                    PublicSharing.Execute(request, profile.Share, new ShareNative(this), result); break;
                case "clone": OwnedClones.Create(selected, profile.CloneParent, request, new HostMetadata(), new CloneNative(this), result); break;
                case "deleteVM": OwnedClones.Delete(selected, profile.OwnedCloneId, new HostMetadata(), new CloneNative(this), result); break;
                case "fileExistsInGuest":
                case "directoryExistsInGuest":
                case "createDirectoryInGuest":
                case "CreateTempfileInGuest":
                case "listDirectoryInGuest":
                case "renameFileInGuest":
                case "deleteFileInGuest":
                case "deleteDirectoryInGuest":
                case "killProcessInGuest":
                case "typeKeystrokesInGuest":
                    ExecuteFixture(request, profile, result); break;
                default: throw new BrokerError("catalog_operation_unavailable");
            }
            return result;
        }
        // Public VIX C ABI: both CopyFile functions have two const-char* paths,
        // int options, handle properties, callback and data. No passwords here.
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GuestPathFn(int vmHandle, IntPtr path, IntPtr callback, IntPtr data);
        private sealed class TransferNative : IPublicTransferNative
        {
            private readonly Vix owner;
            internal TransferNative(Vix owner) { this.owner = owner; }
            public bool Exists(string path, bool directory)
            {
                int job = owner.Function<GuestPathFn>(directory ? "VixVM_DirectoryExistsInGuest" : "VixVM_FileExistsInGuest")(owner.vm, owner.RetainMetadataText(path), IntPtr.Zero, IntPtr.Zero);
                try
                {
                    owner.Complete(job); owner.RequireType(job, 3011, 3);
                    IntPtr value = Marshal.AllocHGlobal(1);
                    try { Marshal.WriteByte(value, 0xff); Success(owner.getPointerProperty(job, 3011, value, 0)); byte exists = Marshal.ReadByte(value); if (exists > 1) throw new BrokerError("transfer_source_refused"); return exists == 1; }
                    finally { Marshal.FreeHGlobal(value); }
                }
                finally { if (job != 0) owner.release(job); }
            }
            public void Info(string path, out long size, out int flags)
            {
                int job = owner.Function<GuestPathFn>("VixVM_GetFileInfoInGuest")(owner.vm, owner.RetainMetadataText(path), IntPtr.Zero, IntPtr.Zero);
                try
                {
                    owner.Complete(job); flags = owner.IntProperty(job, 3054); owner.RequireType(job, 3061, 5);
                    IntPtr value = Marshal.AllocHGlobal(8);
                    try { Marshal.WriteInt64(value, -1); Success(owner.getPointerProperty(job, 3061, value, 0)); size = Marshal.ReadInt64(value); }
                    finally { Marshal.FreeHGlobal(value); }
                }
                finally { if (job != 0) owner.release(job); }
            }
            public void Copy(string source, string destination, bool toGuest)
            {
                owner.EmptyJob(owner.Function<RunPointerFn>(toGuest ? "VixVM_CopyFileFromHostToGuest" : "VixVM_CopyFileFromGuestToHost")(owner.vm, owner.RetainMetadataText(source), owner.RetainMetadataText(destination), 0, 0, IntPtr.Zero, IntPtr.Zero));
            }
        }
        private sealed class CloneNative : ICloneNative
        {
            private readonly Vix owner;
            internal CloneNative(Vix owner) { this.owner = owner; }
            public int Power() { return owner.IntProperty(owner.vm, 129); }
            public void Clone(string destination)
            {
                int clone = owner.ResultHandle(owner.Function<CloneFn>("VixVM_Clone")(owner.vm, 0, 0, owner.RetainMetadataText(destination), 0, 0, IntPtr.Zero, IntPtr.Zero));
                try { Policy.RequireSameTargetPath(owner.PathProperty(clone), destination); }
                finally { owner.release(clone); }
            }
            public void Delete() { owner.EmptyJob(owner.Function<Op4>("VixVM_Delete")(owner.vm, 2, IntPtr.Zero, IntPtr.Zero)); }
        }
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ShareQueryFn(int vmHandle, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ShareWriteFn(int vmHandle, IntPtr name, IntPtr path, int flags, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ShareEnableFn(int vmHandle, byte enabled, int flags, IntPtr callback, IntPtr data);
        private sealed class ShareNative : IPublicShareNative
        {
            private readonly Vix owner;
            internal ShareNative(Vix owner) { this.owner = owner; }
            public int Count()
            {
                int job = owner.Function<ShareQueryFn>("VixVM_GetNumSharedFolders")(owner.vm, IntPtr.Zero, IntPtr.Zero);
                try { owner.Complete(job); int count = owner.IntProperty(job, 3046); if (count < 0 || count > 16) throw new BrokerError("public_share_foreign_mapping"); return count; }
                finally { if (job != 0) owner.release(job); }
            }
            public bool Matches(PublicShare share, int flags)
            {
                int job = owner.Function<Op4>("VixVM_GetSharedFolderState")(owner.vm, 0, IntPtr.Zero, IntPtr.Zero);
                IntPtr name = IntPtr.Zero, path = IntPtr.Zero;
                try
                {
                    owner.Complete(job); owner.RequireType(job, 3035, 2); owner.RequireType(job, 3048, 2);
                    Success(owner.getString(job, 3035, out name, 0)); Success(owner.getString(job, 3048, out path, 0));
                    return owner.IntProperty(job, 3049) == flags && EqualText(name, share.Name) && EqualText(path, share.Root.Path);
                }
                finally { if (name != IntPtr.Zero) owner.free(name); if (path != IntPtr.Zero) owner.free(path); if (job != 0) owner.release(job); }
            }
            private static bool EqualText(IntPtr actual, string expected)
            {
                if (actual == IntPtr.Zero) return false;
                byte[] bytes = new UTF8Encoding(false, true).GetBytes(expected);
                for (int i = 0; i < bytes.Length; i++) if (Marshal.ReadByte(actual, i) != bytes[i]) return false;
                return Marshal.ReadByte(actual, bytes.Length) == 0; // No raw native names/paths become output or managed strings.
            }
            public void Add(PublicShare share) { Write("VixVM_AddSharedFolder", share, 0); }
            public void Set(PublicShare share, int flags) { Write("VixVM_SetSharedFolderState", share, flags); }
            private void Write(string symbol, PublicShare share, int flags)
            { owner.EmptyJob(owner.Function<ShareWriteFn>(symbol)(owner.vm, owner.RetainMetadataText(share.Name), owner.RetainMetadataText(share.Root.Path), flags, IntPtr.Zero, IntPtr.Zero)); }
            public void Enable() { owner.EmptyJob(owner.Function<ShareEnableFn>("VixVM_EnableSharedFolders")(owner.vm, 1, 0, IntPtr.Zero, IntPtr.Zero)); }
        }
        private void ExecuteFixture(VmrunRequest request, CapabilityProfile profile, OperationReport result)
        {
            string primary = NativePlans.Symbol(request); bool mutation = request.IsFixtureStart || GuestFixture.Mutation(request.Entry.Name);
            GuestFixture fixture = profile.Fixture(GuestFixture.RootAlias(request));
            IntPtr helperPath = RetainMetadataText(fixture.HelperPath), helperArgs = RetainMetadataText(fixture.Arguments(selected, request));
            int fixtureJob = 0;
            try
            {
                // Only the reserved fixed PUBLIC GUI launcher receives
                // ACTIVATE_WINDOW2 after REQUIRE_INTERACTIVE_ENVIRONMENT8
                // login. No RETURN_IMMEDIATELY1, guessed4, generic UI flag,
                // forced desktop/focus or changed helper TTL is introduced.
                fixtureJob = Function<RunPointerFn>(primary)(vm, helperPath, helperArgs, NativePlans.Flags(request), 0, IntPtr.Zero, IntPtr.Zero);
                Complete(fixtureJob); int actualType;
                long status = ReadGuestExit(fixtureJob, out actualType); result.GuestExitPropertyType = actualType;
                if (request.IsFixtureStart || GuestFixture.ProcessStop(request.Entry.Name) || GuestFixture.ProcessType(request.Entry.Name)) GuestFixture.CompleteProcess(result, request, fixture.Alias, status);
                else if (request.IsGeneratedFixture) GuestFixture.CompleteGenerated(result, request, fixture.Alias, status);
                else if (request.IsApprovedListing) GuestFixture.CompleteApproved(result, fixture.Alias, fixture.NamedPlan(request.Arguments[1]), status);
                else GuestFixture.Complete(result, fixture.Alias, status);
            }
            catch (BrokerError error)
            {
                // A dispatched helper can outlive failed VIX completion or
                // an unavailable exit property. Never call that a safe refusal.
                if (mutation && error.Code != "guest_fixture_helper_refused") throw new BrokerError("guest_fixture_mutation_uncertain");
                throw;
            }
            catch (Exception)
            { if (mutation) throw new BrokerError("guest_fixture_mutation_uncertain"); throw; }
            finally { if (fixtureJob != 0) release(fixtureJob); }
        }
        private List<SnapshotItem> Snapshots()
        {
            var result = new List<SnapshotItem>();
            try
            {
                int count; Success(Function<NumSnapshotsFn>("VixVM_GetNumRootSnapshots")(vm, out count));
                if (count < 0 || count > 256) throw new BrokerError("native_result_limit");
                for (int i = 0; i < count; i++)
                {
                    int handle; Success(Function<SnapshotAtFn>("VixVM_GetRootSnapshot")(vm, i, out handle));
                    AddSnapshot(result, handle, i.ToString(System.Globalization.CultureInfo.InvariantCulture), 0);
                }
                return result;
            }
            catch { foreach (SnapshotItem item in result) release(item.Handle); throw; }
        }
        private void AddSnapshot(List<SnapshotItem> items, int handle, string reference, int depth)
        {
            if (handle == 0) throw new BrokerError("invalid_vix_result_handle");
            if (items.Count >= 256 || depth >= 16) { release(handle); throw new BrokerError("native_result_limit"); }
            items.Add(new SnapshotItem { Handle = handle, Reference = reference });
            int count; Success(Function<NumSnapshotsFn>("VixSnapshot_GetNumChildren")(handle, out count));
            if (count < 0 || count > 256) throw new BrokerError("native_result_limit");
            for (int i = 0; i < count; i++)
            {
                int child; Success(Function<SnapshotAtFn>("VixSnapshot_GetChild")(handle, i, out child));
                AddSnapshot(items, child, reference + "/" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), depth + 1);
            }
        }
        private string SnapshotLabel(int handle)
        {
            RequireType(handle, 4200, 2);
            IntPtr text = IntPtr.Zero;
            try
            {
                Success(getString(handle, 4200, out text, 0));
                if (text == IntPtr.Zero) throw new BrokerError("native_result_limit");
                int length = 0; while (length <= 512 && Marshal.ReadByte(text, length) != 0) length++;
                if (length > 512) throw new BrokerError("native_result_limit");
                var bytes = new byte[length]; Marshal.Copy(text, bytes, 0, length);
                return new UTF8Encoding(false, true).GetString(bytes); // Internal match only; never output.
            }
            finally { if (text != IntPtr.Zero) free(text); }
        }
    }
}
