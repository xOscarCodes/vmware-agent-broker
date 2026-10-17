using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static partial class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes { internal int Size; internal IntPtr Descriptor; internal int Inherit; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct StartupInfo
        {
            internal int Size;
            internal IntPtr Reserved, Desktop, Title;
            internal uint X, Y, Width, Height, CharsX, CharsY, Fill, Flags;
            internal short Show, ReservedBytes;
            internal IntPtr ReservedData, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct StartupInfoEx { internal StartupInfo Startup; internal IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessInformation { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr destinationProcess, out IntPtr destination, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr bytes, IntPtr previous, IntPtr returnedSize);
        [DllImport("kernel32.dll")]
        internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
        [DllImport("kernel32.dll")]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PeekNamedPipe(SafePipeHandle pipe, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr remaining);
    }

#if !GUEST_HELPER
    internal sealed class WorkerProcess : IDisposable
    {
        private IntPtr process;
        private WorkerProcess(IntPtr handle) { process = handle; }
        internal static WorkerProcess Start(string executable, string[] args, AnonymousPipeServerStream pipe)
        {
            var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)), Inherit = 1 };
            using (SafeFileHandle nul = Native.CreateFileW("NUL", 0xC0000000, 3, ref security, 3, 0x80, IntPtr.Zero))
            {
                if (nul.IsInvalid) throw new BrokerError("worker_start_failed");
                IntPtr parent = IntPtr.Zero, attributes = IntPtr.Zero, handles = IntPtr.Zero;
                bool initialized = false;
                try
                {
                    // Worker may only wait for its parent, not inspect its memory.
                    if (!Native.DuplicateHandle(new IntPtr(-1), new IntPtr(-1), new IntPtr(-1), out parent, 0x100000, true, 0)) throw new BrokerError("worker_start_failed");
                    IntPtr size = IntPtr.Zero;
                    Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                    if (size.ToInt64() < 1 || size.ToInt64() > 65536) throw new BrokerError("worker_start_failed");
                    attributes = Marshal.AllocHGlobal(size);
                    if (!Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new BrokerError("worker_start_failed");
                    initialized = true;
                    handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                    Marshal.WriteIntPtr(handles, 0, pipe.ClientSafePipeHandle.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, IntPtr.Size, nul.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, IntPtr.Size * 2, parent);
                    if (!Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw new BrokerError("worker_start_failed");
                    var startup = new Native.StartupInfoEx();
                    startup.Startup.Size = Marshal.SizeOf(typeof(Native.StartupInfoEx));
                    startup.Startup.Flags = 0x100; // STARTF_USESTDHANDLES: discard all vendor/CLR text.
                    startup.Startup.Input = startup.Startup.Output = startup.Startup.Error = nul.DangerousGetHandle();
                    startup.Attributes = attributes;
                    var command = new StringBuilder("\"" + executable + "\" --broker-worker " + pipe.GetClientHandleAsString() + " " + parent.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture));
                    // Only canonical, already-validated request tokens or fixed synthetic
                    // test tokens. No credentials or caller-selected executable/shell.
                    command.Append(' ').Append(WindowsArguments.Join(args));
                    Native.ProcessInformation child;
                    if (!Native.CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true, 0x80000 | 0x08000000, IntPtr.Zero, System.IO.Path.GetDirectoryName(executable), ref startup, out child))
                        throw new BrokerError("worker_start_failed");
                    Native.CloseHandle(child.Thread);
                    return new WorkerProcess(child.Process);
                }
                finally
                {
                    if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                    if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                    if (parent != IntPtr.Zero) Native.CloseHandle(parent);
                    pipe.DisposeLocalCopyOfClientHandle();
                }
            }
        }
        internal bool Wait(uint milliseconds) { return Native.WaitForSingleObject(process, milliseconds) == 0; }
        internal uint ExitCode
        {
            get { uint code; if (!Native.GetExitCodeProcess(process, out code)) throw new BrokerError("worker_status_failed"); return code; }
        }
        internal void Stop(uint code) { if (!Wait(0)) { Native.TerminateProcess(process, code); Wait(5000); } }
        public void Dispose() { if (process != IntPtr.Zero) { Stop(125); Native.CloseHandle(process); process = IntPtr.Zero; } }
    }
#endif
}
