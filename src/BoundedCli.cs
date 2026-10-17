using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static class BoundedCli
    {
        // Internal test seam uses only this utility's synthetic test executable.
        // Production callers pass verified, fixed official tool paths/plans.
        internal static CliReply Run(string executable, string[] arguments, bool readOutput, int timeout, int limit, Func<bool> fileWithinLimit)
        {
            if (timeout < 1 || timeout > 30000 || limit < 1 || limit > 32768) throw new BrokerError("cli_plan_forbidden");
            var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)), Inherit = 1 };
            IntPtr job = IntPtr.Zero, process = IntPtr.Zero, thread = IntPtr.Zero, attributes = IntPtr.Zero, handles = IntPtr.Zero;
            bool initialized = false;
            using (var pipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
            using (SafeFileHandle nul = Native.CreateFileW("NUL", 0xC0000000, 3, ref security, 3, 0x80, IntPtr.Zero))
            using (var data = new MemoryStream())
            {
                byte[] buffer = new byte[4096];
                try
                {
                    if (nul.IsInvalid) throw new BrokerError("cli_start_failed");
                    job = Native.CreateJobObjectW(IntPtr.Zero, null);
                    var limits = new Native.JobLimits();
                    // Kill ONLY the direct tool on worker death. Vendor-created child
                    // helpers break away; existing VM/service processes are not owned
                    // by this job and are never killed. This is NOT a sandbox.
                    limits.Basic.Flags = 0x2000 | 0x1000;
                    if (job == IntPtr.Zero || !Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Native.JobLimits)))) throw new BrokerError("cli_isolation_unavailable");
                    IntPtr size = IntPtr.Zero; Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                    if (size.ToInt64() < 1 || size.ToInt64() > 65536) throw new BrokerError("cli_start_failed");
                    attributes = Marshal.AllocHGlobal(size);
                    if (!Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new BrokerError("cli_start_failed");
                    initialized = true;
                    int count = readOutput ? 2 : 1;
                    handles = Marshal.AllocHGlobal(IntPtr.Size * count);
                    Marshal.WriteIntPtr(handles, 0, nul.DangerousGetHandle());
                    if (readOutput) Marshal.WriteIntPtr(handles, IntPtr.Size, pipe.ClientSafePipeHandle.DangerousGetHandle());
                    if (!Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles, new IntPtr(IntPtr.Size * count), IntPtr.Zero, IntPtr.Zero)) throw new BrokerError("cli_start_failed");
                    var startup = new Native.StartupInfoEx();
                    startup.Startup.Size = Marshal.SizeOf(typeof(Native.StartupInfoEx)); startup.Attributes = attributes;
                    startup.Startup.Flags = 0x100; startup.Startup.Input = startup.Startup.Error = nul.DangerousGetHandle();
                    startup.Startup.Output = readOutput ? pipe.ClientSafePipeHandle.DangerousGetHandle() : nul.DangerousGetHandle();
                    var command = new StringBuilder(WindowsArguments.Quote(executable) + " " + WindowsArguments.Join(arguments));
                    Native.ProcessInformation child;
                    if (!Native.CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true, 0x80000 | 0x08000000 | 4, IntPtr.Zero, Path.GetDirectoryName(executable), ref startup, out child)) throw new BrokerError("cli_start_failed");
                    process = child.Process; thread = child.Thread;
                    // Suspended until lifetime control is established; fail closed
                    // before ANY command runs if nested jobs are unavailable.
                    if (!Native.AssignProcessToJobObject(job, process)) throw new BrokerError("cli_isolation_unavailable");
                    if (Native.ResumeThread(thread) == 0xffffffff) throw new BrokerError("cli_start_failed");
                    Native.CloseHandle(thread); thread = IntPtr.Zero;
                    pipe.DisposeLocalCopyOfClientHandle();
                    var clock = Stopwatch.StartNew();
                    for (;;)
                    {
                        if (fileWithinLimit != null && !fileWithinLimit()) throw new BrokerError("private_export_limit");
                        if (clock.ElapsedMilliseconds > timeout) throw new BrokerError("official_cli_timeout");
                        uint available = 0;
                        bool peek = readOutput && Native.PeekNamedPipe(pipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero);
                        if (peek && available != 0)
                        {
                            int n = pipe.Read(buffer, 0, (int)Math.Min(available, (uint)buffer.Length));
                            if (data.Length + n > limit) throw new BrokerError("cli_output_limit");
                            data.Write(buffer, 0, n); Array.Clear(buffer, 0, buffer.Length); continue;
                        }
                        if (Native.WaitForSingleObject(process, 0) == 0)
                        {
                            if (readOutput && Native.PeekNamedPipe(pipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero) && available != 0) continue;
                            break;
                        }
                        Native.WaitForSingleObject(process, 20);
                    }
                    uint exit; if (!Native.GetExitCodeProcess(process, out exit)) throw new BrokerError("cli_status_failed");
                    return new CliReply { Exit = exit, Output = data.ToArray() };
                }
                finally
                {
                    if (process != IntPtr.Zero) { if (Native.WaitForSingleObject(process, 0) != 0) { Native.TerminateProcess(process, 124); Native.WaitForSingleObject(process, 5000); } Native.CloseHandle(process); }
                    if (thread != IntPtr.Zero) Native.CloseHandle(thread);
                    if (job != IntPtr.Zero) Native.CloseHandle(job);
                    if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                    if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                    pipe.DisposeLocalCopyOfClientHandle();
                    Array.Clear(buffer, 0, buffer.Length);
                    if (data.Capacity != 0) Array.Clear(data.GetBuffer(), 0, data.Capacity);
                }
            }
        }
    }
}
