using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace GuestBroker
{
    // Public VIX C declarations only. x86 cdecl, int32 handles/property IDs, uint64
    // errors, one-byte VMware Bool (NOT Win32 BOOL). No private/vendor schemas.
    internal sealed partial class Vix : IBrokerSession
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ConnectFn(int version, int provider, IntPtr host, int port, IntPtr user, IntPtr password, int options, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int OpenFn(int host, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int options, int properties, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong CheckFn(int job, out byte complete);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong ErrorFn(int job);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ReleaseFn(int handle);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void FreeFn(IntPtr buffer);
        // Fixed adapters to C variadic calls. Only these exact int/pointer argument
        // lists are emitted; cdecl x86 passes all of them on the stack.
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong GetIntFn(int handle, int property, out int value, int end);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong GetStringFn(int handle, int property, out IntPtr value, int end);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong GetTypeFn(int handle, int property, out int type);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int LoginFn(int vm, IntPtr user, IntPtr password, int options, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int LogoutFn(int vm, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ReadVariableFn(int vm, int type, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, int options, IntPtr callback, IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int RunFn(int vm, [MarshalAs(UnmanagedType.LPUTF8Str)] string program, [MarshalAs(UnmanagedType.LPUTF8Str)] string arguments, int options, int properties, IntPtr callback, IntPtr data);

        private IntPtr module;
        private FileStream dllFile, vmxFile;
        private ConnectFn connect;
        private OpenFn open;
        private CheckFn check;
        private ErrorFn jobError;
        private ReleaseFn release, disconnect;
        private FreeFn free;
        private GetIntFn getInt;
        private GetStringFn getString;
        private GetTypeFn getType;
        private LoginFn login;
        private LogoutFn logout;
        private ReadVariableFn readVariable;
        private RunFn run;
        private int host, vm;
        private bool loggedIn;
        private bool operationPrepared;
        private int preparedLoginOptions; // Default0 for legacy/generic sessions; only PrepareOperation can select fixed8.
        private Target selected;
        private Deadline deadline;
        public int ApiVersion { get; private set; }

        private T Function<T>(string name) where T : class
        {
            IntPtr address = Native.GetProcAddress(module, name);
            if (address == IntPtr.Zero) throw new BrokerError("missing_vix_export");
            return Marshal.GetDelegateForFunctionPointer(address, typeof(T)) as T;
        }

        internal Vix()
        {
            try
            {
                deadline = new Deadline();
                Diagnostics.At(Stage.NativeLoad);
                if (IntPtr.Size != 4) throw new BrokerError("unsupported_broker_architecture");
                if (!Native.SetDefaultDllDirectories(0x800)) throw new BrokerError("secure_loader_unavailable");
                dllFile = Policy.OpenPinned(Policy.Dll);
                if (dllFile.Length < 4096 || dllFile.Length > 16 * 1024 * 1024) throw new BrokerError("invalid_vix_size");
                Policy.VerifyHash(dllFile);
                byte[] header = new byte[4096];
                int count = dllFile.Read(header, 0, header.Length);
                if (count != header.Length) throw new BrokerError("invalid_pe");
                Policy.VerifyImage(header);
                VerifySignature(dllFile);
                // Process-local only. No CWD/PATH/application directory search.
                module = Native.LoadLibraryExW(Policy.Dll, IntPtr.Zero, 0x100 | 0x800);
                if (module == IntPtr.Zero) throw new BrokerError("vix_load_failed");
                var actual = new StringBuilder(1024);
                uint n = Native.GetModuleFileNameW(module, actual, actual.Capacity);
                if (n == 0 || n >= actual.Capacity || !String.Equals(actual.ToString(), Policy.Dll, StringComparison.OrdinalIgnoreCase))
                    throw new BrokerError("loaded_module_mismatch");
                connect = Function<ConnectFn>("VixHost_Connect");
                open = Function<OpenFn>("VixHost_OpenVM");
                check = Function<CheckFn>("VixJob_CheckCompletion");
                jobError = Function<ErrorFn>("VixJob_GetError");
                release = Function<ReleaseFn>("Vix_ReleaseHandle");
                disconnect = Function<ReleaseFn>("VixHost_Disconnect");
                free = Function<FreeFn>("Vix_FreeBuffer");
                getInt = Function<GetIntFn>("Vix_GetProperties");
                getString = Function<GetStringFn>("Vix_GetProperties");
                getType = Function<GetTypeFn>("Vix_GetPropertyType");
                login = Function<LoginFn>("VixVM_LoginInGuest");
                logout = Function<LogoutFn>("VixVM_LogoutFromGuest");
                readVariable = Function<ReadVariableFn>("VixVM_ReadVariable");
                run = Function<RunFn>("VixVM_RunProgramInGuest");
                // No host credentials, remote hostname, UI launch, or default provider.
                Diagnostics.At(Stage.HostConnect);
                host = ResultHandle(connect(-1, 3, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, 0, 0, IntPtr.Zero, IntPtr.Zero));
                ApiVersion = IntProperty(host, 51);
                // This installation returns the requested latest-version sentinel
                // (-1), NOT the wrapper mapping's 19. Do not confuse these fields.
                if (ApiVersion != -1) throw new BrokerError("unexpected_vix_api_property");
            }
            catch { Dispose(); throw; }
        }

        private static void VerifySignature(FileStream file)
        {
            var info = new Native.TrustFile();
            info.Size = (uint)Marshal.SizeOf(typeof(Native.TrustFile));
            info.Path = Policy.Dll;
            info.File = file.SafeFileHandle.DangerousGetHandle();
            IntPtr ptr = Marshal.AllocHGlobal((int)info.Size);
            Marshal.StructureToPtr(info, ptr, false);
            var trust = new Native.TrustData();
            trust.Size = (uint)Marshal.SizeOf(typeof(Native.TrustData));
            trust.Ui = 2; // WTD_UI_NONE
            trust.UnionChoice = 1; // WTD_CHOICE_FILE
            trust.File = ptr;
            trust.StateAction = 1;
            trust.Flags = 0x1000 | 0x10; // Cache-only retrieval, no online revocation.
            var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            try
            {
                if (Native.WinVerifyTrust(new IntPtr(-1), ref action, ref trust) != 0) throw new BrokerError("vix_signature_untrusted");
            }
            finally
            {
                trust.StateAction = 2;
                Native.WinVerifyTrust(new IntPtr(-1), ref action, ref trust);
                Marshal.DestroyStructure(ptr, typeof(Native.TrustFile));
                Marshal.FreeHGlobal(ptr);
                GC.KeepAlive(file);
            }
        }

        private static void Success(ulong error)
        {
            if (error != 0) throw new BrokerError("vix_error_" + (error & 0xffff).ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        private void Complete(int job)
        {
            if (job == 0) throw new BrokerError("invalid_vix_job");
            // A process watchdog covers native calls that themselves hang. Do not
            // release incomplete jobs/passwords or unload code still using them.
            for (; ; )
            {
                byte done;
                Success(check(job, out done));
                if (done != 0) break;
                Thread.Sleep(25);
            }
            Success(jobError(job));
        }

        private int ResultHandle(int job)
        {
            try
            {
                Complete(job);
                int result = IntProperty(job, 3010);
                if (result == 0) throw new BrokerError("invalid_vix_result_handle");
                return result;
            }
            finally { if (job != 0) release(job); }
        }

        private int IntProperty(int handle, int property)
        {
            RequireType(handle, property, property == 3010 ? 4 : 1);
            int result;
            Success(getInt(handle, property, out result, 0));
            return result;
        }

        private void RequireType(int handle, int property, int expected)
        {
            int type;
            Success(getType(handle, property, out type));
            if (type != expected) { Diagnostics.PropertyMismatch(property, expected.ToString(System.Globalization.CultureInfo.InvariantCulture), type); throw new BrokerError("vix_property_type_mismatch"); }
        }

        private void EmptyJob(int job)
        {
            try { Complete(job); }
            finally { if (job != 0) release(job); }
        }

        public void OpenTarget(Target target)
        {
            Diagnostics.At(Stage.TargetOpen);
            if (vm != 0) throw new BrokerError("target_already_open");
            vmxFile = VmIdentity.Open(target);
            vm = ResultHandle(open(host, target.Vmx, 0, 0, IntPtr.Zero, IntPtr.Zero));
            Policy.RequireSameTargetPath(PathProperty(vm), target.Vmx);
            selected = target.Clone();
        }
        public IDisposable UserInteraction()
        {
            // Do not keep a host config-write lock while waiting for the human.
            // Revalidate path/UUID/file ID and native handle before login.
            if (vmxFile != null) { vmxFile.Dispose(); vmxFile = null; }
            return deadline.Pause();
        }
        public void Revalidate(Target target)
        {
            Diagnostics.At(Stage.TargetValidate);
            if (selected == null || !selected.SameRegistrationVersion(target)) throw new BrokerError("registration_changed");
            if (vmxFile != null) { vmxFile.Dispose(); vmxFile = null; }
            vmxFile = VmIdentity.Open(target);
            Policy.RequireSameTargetPath(PathProperty(vm), target.Vmx);
        }

        private string PathProperty(int handle)
        {
            RequireType(handle, 103, 2); // VIX_PROPERTY_VM_VMX_PATHNAME
            IntPtr text = IntPtr.Zero;
            try
            {
                Success(getString(handle, 103, out text, 0));
                if (text == IntPtr.Zero) throw new BrokerError("native_target_mismatch");
                int length = 0;
                while (length <= 1024 && Marshal.ReadByte(text, length) != 0) length++;
                if (length == 0 || length > 1024) throw new BrokerError("native_target_mismatch");
                var bytes = new byte[length]; // Public path metadata, never credentials.
                Marshal.Copy(text, bytes, 0, length);
                return new UTF8Encoding(false, true).GetString(bytes);
            }
            finally { if (text != IntPtr.Zero) free(text); }
        }

        public string Status()
        {
            Diagnostics.At(Stage.StatusRead);
            int tools = IntProperty(vm, 152), power = IntProperty(vm, 129);
            return "\"powerState\":" + power.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                ",\"toolsState\":" + tools.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        public void Login(GuestCredential credential)
        {
            if (selected == null || credential.Binding != selected.Binding) throw new BrokerError("credential_target_mismatch");
            if (utf8User != null) throw new BrokerError("login_already_attempted");
            // Retained even on failed login until native VM/host teardown. No
            // assumption about asynchronous copies of these C string arguments.
            Diagnostics.At(Stage.CredentialUtf8);
            utf8User = credential.User.Utf8();
            utf8Password = credential.Password.Utf8();
            GuestUsernameNormalization.Login(credential.User, utf8User, preparedLoginOptions, new UsernameLogin(this));
        }
        private sealed class UsernameLogin : IGuestUsernameLogin
        {
            private readonly Vix owner;
            internal UsernameLogin(Vix owner) { this.owner = owner; }
            public void Authenticate(SecretBuffer user, int options) { owner.Authenticate(user, options); }
            public string ComputerName() { return owner.Identity(); } // Fixed native guestEnv COMPUTERNAME only.
            public void Logout()
            {
                if (!owner.loggedIn) throw new BrokerError("credential_unavailable");
                owner.loggedIn = false;
                Diagnostics.At(Stage.GuestLogout);
                owner.EmptyJob(owner.logout(owner.vm, IntPtr.Zero, IntPtr.Zero));
            }
            public void Revalidate() { owner.Revalidate(owner.selected); }
            public void Retain(SecretBuffer user)
            {
                if (owner.utf8InteractiveUser != null) throw new BrokerError("login_already_attempted");
                owner.utf8InteractiveUser = user;
            }
        }
        private void Authenticate(SecretBuffer user, int options)
        {
            Diagnostics.At(Stage.GuestLogin);
            int job = login(vm, user.Pointer, utf8Password.Pointer, options, IntPtr.Zero, IntPtr.Zero);
            Diagnostics.At(Stage.GuestLoginWait);
            EmptyJob(job);
            loggedIn = true;
        }

        private SecretBuffer utf8User, utf8Password, utf8InteractiveUser;

        public string Identity()
        {
            Diagnostics.At(Stage.GuestIdentity);
            int job = readVariable(vm, 3, "COMPUTERNAME", 0, IntPtr.Zero, IntPtr.Zero);
            IntPtr text = IntPtr.Zero;
            try
            {
                Complete(job);
                RequireType(job, 3056, 2);
                Success(getString(job, 3056, out text, 0));
                if (text == IntPtr.Zero) throw new BrokerError("invalid_guest_identity");
                int length = 0;
                while (length <= 63 && Marshal.ReadByte(text, length) != 0) length++;
                if (length == 0 || length > 63) throw new BrokerError("invalid_guest_identity");
                // Only this bounded non-secret hostname is converted to managed text.
                return Policy.SafeHostname(Marshal.PtrToStringAnsi(text, length));
            }
            finally { if (text != IntPtr.Zero) free(text); if (job != 0) release(job); }
        }

        public void SetMelbourneTimezone()
        {
            Diagnostics.At(Stage.GuestProgram);
            int job = run(vm, Policy.TimezoneProgram, Policy.TimezoneArguments, 0, 0, IntPtr.Zero, IntPtr.Zero);
            Diagnostics.At(Stage.GuestProgramWait);
            try
            {
                Complete(job);
                // Same checked, runtime-width reader as program/script/helper
                // results; never infer INTEGER vs INT64 from the property name.
                int actualType;
                if (ReadGuestExit(job, out actualType) != 0) throw new BrokerError("guest_program_failed");
            }
            finally { if (job != 0) release(job); }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong GetPointerFn(int handle, int property, IntPtr value, int end);
        private ulong getPointerProperty(int handle, int property, IntPtr value, int end)
        {
            return Function<GetPointerFn>("Vix_GetProperties")(handle, property, value, end);
        }
        private long ReadGuestExit(int job, out int actualType)
        {
            Success(getType(job, GuestExitReader.Property, out actualType));
            return GuestExitReader.Read(actualType, delegate (IntPtr value) { Success(getPointerProperty(job, GuestExitReader.Property, value, 0)); });
        }

        public void Dispose()
        {
            // On success and errors, close the authenticated session before wiping
            // input allocations or unloading its native implementation.
            try
            {
                if (loggedIn && vm != 0)
                {
                    loggedIn = false;
                    Diagnostics.At(Stage.GuestLogout);
                    EmptyJob(logout(vm, IntPtr.Zero, IntPtr.Zero));
                }
            }
            finally
            {
                if (preparedSnapshots != null) { foreach (SnapshotItem snapshot in preparedSnapshots) release(snapshot.Handle); preparedSnapshots = null; preparedSnapshot = 0; }
                if (vm != 0) { Diagnostics.At(Stage.VmRelease); release(vm); vm = 0; }
                if (host != 0) { Diagnostics.At(Stage.HostDisconnect); disconnect(host); host = 0; }
                // Deliberately retain the loader reference until worker exit. Public
                // declarations do not establish vendor background-thread quiescence.
                // No explicit FreeLibrary/reload cycle around user UI or login.
                module = IntPtr.Zero;
                Diagnostics.At(Stage.SecretCleanup);
                if (preparedScript != null) { preparedScript.Dispose(); preparedScript = null; }
                if (preparedTransfer != null) { preparedTransfer.Dispose(); preparedTransfer = null; }
                foreach (SecretBuffer text in operationText) text.Dispose();
                operationText.Clear();
                if (utf8User != null) { utf8User.Dispose(); utf8User = null; }
                if (utf8InteractiveUser != null) { utf8InteractiveUser.Dispose(); utf8InteractiveUser = null; }
                if (utf8Password != null) { utf8Password.Dispose(); utf8Password = null; }
                if (vmxFile != null) { vmxFile.Dispose(); vmxFile = null; }
                if (dllFile != null) { dllFile.Dispose(); dllFile = null; }
                if (deadline != null) { deadline.Dispose(); deadline = null; }
            }
        }
    }
}
