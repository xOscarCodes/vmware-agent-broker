using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace GuestBroker
{
    internal static partial class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsProcessCritical(IntPtr process, [MarshalAs(UnmanagedType.Bool)] out bool critical);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    }
    internal sealed class FixtureImagePin : IDisposable
    {
        private PinnedDirectory parent; private FileStream file;
        internal string Path { get; private set; }
        internal static FixtureImagePin Open(string hash)
        {
            string path = typeof(GuestProcessSupervisor).Assembly.Location; var pin = new FixtureImagePin { Path = path };
            try
            {
                pin.parent = PinnedDirectory.Open(System.IO.Path.GetDirectoryName(path)); pin.file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                HostPaths.CheckHandle(pin.file.SafeFileHandle, path, false);
                if (FixtureProtocol.ImageHash(path) != hash) throw new BrokerError("guest_fixture_process_refused"); return pin;
            }
            catch { pin.Dispose(); throw; }
        }
        public void Dispose() { if (file != null) { file.Dispose(); file = null; } if (parent != null) { parent.Dispose(); parent = null; } }
    }
    internal sealed class OwnedFixtureProcess : IDisposable
    {
        private IntPtr process, thread, job;
        private readonly string image;
        internal uint Id { get; private set; }
        internal long Created { get; private set; }
        private bool detached;
        private bool suspended;
        private OwnedFixtureProcess(string path) { image = path; }
        internal static OwnedFixtureProcess Start(FixtureImagePin image, string[] arguments, bool ownedFixture, AnonymousPipeServerStream commands = null, AnonymousPipeServerStream replies = null)
        {
            var result = new OwnedFixtureProcess(image.Path);
            var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)), Inherit = 1 };
            using (var nul = Native.CreateFileW("NUL", 0xC0000000, 3, ref security, 3, 0x80, IntPtr.Zero))
            {
                IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero, jobValue = IntPtr.Zero, inheritedJob = IntPtr.Zero, environment = IntPtr.Zero; bool initialized = false; int environmentBytes = 0;
                try
                {
                    if (nul.IsInvalid) throw new BrokerError("guest_fixture_process_refused");
                    bool creatorCritical;
                    if (!Native.IsProcessCritical(new IntPtr(-1), out creatorCritical) || creatorCritical) throw new BrokerError("guest_fixture_process_refused"); // Require this public guard before creating anything.
                    result.job = Native.CreateJobObjectW(IntPtr.Zero, null); var limits = new Native.JobLimits(); limits.Basic.Flags = 0x2000;
                    if (result.job == IntPtr.Zero || !Native.SetInformationJobObject(result.job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Native.JobLimits)))) throw new BrokerError("guest_fixture_process_refused");
                    var actualArgs = new List<string>(arguments);
                    if (!ownedFixture)
                    {
                        if (!Native.DuplicateHandle(new IntPtr(-1), result.job, new IntPtr(-1), out inheritedJob, 0, true, 2)) throw new BrokerError("guest_fixture_process_refused");
                        actualArgs.Add("--owner-job"); actualArgs.Add(inheritedJob.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture));
                    }
                    IntPtr size = IntPtr.Zero; Native.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                    if (size.ToInt64() < 1 || size.ToInt64() > 65536) throw new BrokerError("guest_fixture_process_refused");
                    attributes = Marshal.AllocHGlobal(size); if (!Native.InitializeProcThreadAttributeList(attributes, 2, 0, ref size)) throw new BrokerError("guest_fixture_process_refused"); initialized = true;
                    if ((commands == null) != (replies == null) || (!ownedFixture && commands != null)) throw new BrokerError("guest_fixture_process_refused");
                    int inheritedCount = ownedFixture ? (commands == null ? 1 : 3) : 2;
                    handles = Marshal.AllocHGlobal(IntPtr.Size * inheritedCount); Marshal.WriteIntPtr(handles, nul.DangerousGetHandle());
                    if (!ownedFixture) Marshal.WriteIntPtr(handles, IntPtr.Size, inheritedJob);
                    if (commands != null) { Marshal.WriteIntPtr(handles, IntPtr.Size, commands.ClientSafePipeHandle.DangerousGetHandle()); Marshal.WriteIntPtr(handles, IntPtr.Size * 2, replies.ClientSafePipeHandle.DangerousGetHandle()); }
                    if (!Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles, new IntPtr(IntPtr.Size * inheritedCount), IntPtr.Zero, IntPtr.Zero)) throw new BrokerError("guest_fixture_process_refused");
                    jobValue = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobValue, result.job);
                    // Public PROC_THREAD_ATTRIBUTE_JOB_LIST (13): atomic job
                    // assignment at process creation, no suspended orphan window.
                    if (!Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000D), jobValue, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) throw new BrokerError("guest_fixture_process_refused");
                    var startup = new Native.StartupInfoEx(); startup.Startup.Size = Marshal.SizeOf(typeof(Native.StartupInfoEx)); startup.Startup.Flags = 0x100;
                    startup.Startup.Input = startup.Startup.Output = startup.Startup.Error = nul.DangerousGetHandle(); startup.Attributes = attributes;
                    string publicEnvironment = PublicEnvironment(); environmentBytes = (publicEnvironment.Length + 1) * 2; environment = Marshal.StringToHGlobalUni(publicEnvironment);
                    Native.ProcessInformation child;
                    if (!Native.CreateProcessW(image.Path, new StringBuilder(WindowsArguments.Quote(image.Path) + " " + WindowsArguments.Join(actualArgs)), IntPtr.Zero, IntPtr.Zero, true, 0x80000u | 0x08000000u | 0x400u | (ownedFixture ? 4u : 0u), environment, System.IO.Path.GetDirectoryName(image.Path), ref startup, out child)) throw new BrokerError("guest_fixture_process_refused");
                    result.process = child.Process; result.thread = child.Thread; result.Id = child.ProcessId;
                    result.suspended = ownedFixture;
                    long exit, kernel, user, created;
                    if (!Native.GetProcessTimes(result.process, out created, out exit, out kernel, out user)) throw new BrokerError("guest_fixture_process_refused"); result.Created = created;
                    if (!result.SafeIdentity()) throw new BrokerError("guest_fixture_process_refused");
                    return result; // Idle fixture suspended; supervisor already runnable and self-expiring.
                }
                catch { bool began = result.process != IntPtr.Zero; result.Dispose(); if (began) throw new BrokerError("guest_fixture_mutation_uncertain"); throw; }
                finally
                {
                    if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes); if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                    if (jobValue != IntPtr.Zero) Marshal.FreeHGlobal(jobValue); if (inheritedJob != IntPtr.Zero) Native.CloseHandle(inheritedJob);
                    if (environment != IntPtr.Zero) { for (int i = 0; i < environmentBytes; i++) Marshal.WriteByte(environment, i, 0); Marshal.FreeHGlobal(environment); }
                }
            }
        }
        internal static string PublicEnvironment()
        {
            // Never clone the caller's environment (credentials, profiler hooks,
            // shell startup variables, etc.). Only these public OS directory paths.
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows), local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "SystemRoot", windows }, { "WINDIR", windows }, { "LOCALAPPDATA", local },
                { "APPDATA", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) },
                { "USERPROFILE", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) },
                { "TEMP", System.IO.Path.Combine(local, "Temp") }, { "TMP", System.IO.Path.Combine(local, "Temp") },
                { "PATH", Environment.GetFolderPath(Environment.SpecialFolder.System) + ";" + windows }
            };
            var block = new StringBuilder();
            foreach (var pair in values)
            {
                if (String.IsNullOrEmpty(pair.Value) || pair.Value.IndexOf('\0') >= 0) throw new BrokerError("guest_fixture_process_refused");
                block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
            }
            block.Append('\0'); if (block.Length > 16384) throw new BrokerError("guest_fixture_process_refused"); return block.ToString();
        }
        internal void Resume() { if (thread == IntPtr.Zero || (suspended && Native.ResumeThread(thread) == 0xffffffff)) throw new BrokerError("guest_fixture_process_refused"); Native.CloseHandle(thread); thread = IntPtr.Zero; suspended = false; }
        internal bool Exited { get { return process != IntPtr.Zero && Native.WaitForSingleObject(process, 0) == 0; } }
#if BROKER_TESTS
        internal uint SafeExitStatus { get { uint status; return Native.GetExitCodeProcess(process, out status) ? status : 0xffffffff; } }
#endif
        internal bool SafeIdentity() { try { return ReadOnlyIdentity(process, Created, image); } catch (Exception) { return false; } }
        internal static bool ReadOnlyIdentity(IntPtr handle, long created, string image)
        {
            long actual, exit, kernel, user; bool critical; uint size = 1024; var path = new StringBuilder(1024);
            return handle != IntPtr.Zero && Native.GetProcessTimes(handle, out actual, out exit, out kernel, out user) && actual == created && Native.IsProcessCritical(handle, out critical) && !critical && Native.QueryFullProcessImageNameW(handle, 0, path, ref size) && String.Equals(path.ToString(), image, StringComparison.OrdinalIgnoreCase);
        }
        internal void Stop()
        {
            if (Exited) return;
            if (!SafeIdentity()) throw new BrokerError("guest_fixture_process_refused");
            if (!Native.TerminateProcess(process, 0) || Native.WaitForSingleObject(process, 5000) != 0) throw new BrokerError("guest_fixture_mutation_uncertain");
        }
        internal void DetachSupervisor() { detached = true; }
        public void Dispose()
        {
            if (process != IntPtr.Zero && !detached && !Exited)
            {
                if (SafeIdentity()) { Native.TerminateProcess(process, 125); Native.WaitForSingleObject(process, 5000); }
                else if (job != IntPtr.Zero) { var limits = new Native.JobLimits(); Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Native.JobLimits))); } // Never knowingly terminate a critical/identity-mismatched process.
            }
            if (thread != IntPtr.Zero) { Native.CloseHandle(thread); thread = IntPtr.Zero; }
            if (job != IntPtr.Zero) { Native.CloseHandle(job); job = IntPtr.Zero; }
            if (process != IntPtr.Zero) { Native.CloseHandle(process); process = IntPtr.Zero; }
        }
    }
}
