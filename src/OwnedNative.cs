using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static partial class Native
    {
        [StructLayout(LayoutKind.Sequential)] internal struct UnicodeName { internal ushort Length, MaximumLength; internal IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] internal struct ObjectAttributes
        { internal uint Length; internal IntPtr Root, Name; internal uint Flags; internal IntPtr Security, Quality; }
        [StructLayout(LayoutKind.Sequential)] internal struct IoStatus { internal IntPtr Status, Information; }
        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern int NtCreateFile(ref IntPtr file, uint access, ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern int NtSetInformationFile(SafeFileHandle file, out IoStatus status, IntPtr buffer, uint bytes, int informationClass);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, IntPtr buffer, uint bytes);
    }
    internal static class OwnedNative
    {
        internal static SafeFileHandle Create(SafeFileHandle parent, string leaf, bool directory)
        { return Open(parent, leaf, directory, true); }
        internal static SafeFileHandle OpenOwnedFile(SafeFileHandle parent, string leaf)
        { return Open(parent, leaf, false, false); }
        internal static SafeFileHandle OpenOwnedObject(SafeFileHandle parent, string leaf, bool directory)
        { return Open(parent, leaf, directory, false); }
        internal static SafeFileHandle CreateGeneratedFile(SafeFileHandle parent, string leaf)
        { return Open(parent, leaf, false, true, true); }
        private static SafeFileHandle Open(SafeFileHandle parent, string leaf, bool directory, bool create, bool generatedWrite = false)
        {
            // RootDirectory is an already validated/pinned directory object; only
            // one validated basename is resolved, never an absolute path or tree.
            if (FixtureProtocol.Relative(leaf).Contains("\\")) throw new BrokerError("guest_fixture_path_rejected");
            IntPtr nameText = Marshal.StringToHGlobalUni(leaf), namePointer = IntPtr.Zero, raw = IntPtr.Zero;
            GCHandle securityPin = new GCHandle();
            try
            {
                var name = new Native.UnicodeName { Length = checked((ushort)(leaf.Length * 2)), MaximumLength = checked((ushort)((leaf.Length + 1) * 2)), Buffer = nameText };
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.UnicodeName))); Marshal.StructureToPtr(name, namePointer, false);
                var attributes = new Native.ObjectAttributes { Length = (uint)Marshal.SizeOf(typeof(Native.ObjectAttributes)), Root = parent.DangerousGetHandle(), Name = namePointer, Flags = 0x40 };
                if (create)
                {
                    byte[] descriptor;
                    if (directory)
                    {
                        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                        {
                            var security = new DirectorySecurity(); security.SetOwner(identity.User); security.SetAccessRuleProtection(true, false);
                            security.AddAccessRule(new FileSystemAccessRule(identity.User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                            descriptor = security.GetSecurityDescriptorBinaryForm();
                        }
                    }
                    else descriptor = HostPaths.FileSecurity().GetSecurityDescriptorBinaryForm();
                    securityPin = GCHandle.Alloc(descriptor, GCHandleType.Pinned); attributes.Security = securityPin.AddrOfPinnedObject();
                }
                Native.IoStatus io;
                // Creation: FILE_CREATE, never open-existing/overwrite. Rename
                // source: FILE_OPEN and DELETE access, only after ledger approval.
                // Normal creation/source deny write/delete sharing and write-data.
                // The separate GENERATED-only new-file factory requests read/write
                // with NO sharing. Never delete-on-close or backup privilege.
                int status = Native.NtCreateFile(ref raw, create ? (generatedWrite ? 0x120083u : 0x120081u) : 0x130081u, ref attributes, out io, IntPtr.Zero, directory ? 0x10u : 0x80u, generatedWrite ? 0u : 1u, create ? 2u : 1u, 0x200000u | 0x20u | (directory ? 1u : 0x40u), IntPtr.Zero, 0);
                if (status < 0)
                {
                    if (raw != IntPtr.Zero && raw != new IntPtr(-1)) Native.CloseHandle(raw); raw = IntPtr.Zero;
                    throw new BrokerError(create ? "guest_fixture_create_refused" : "guest_fixture_owned_refused");
                }
                if (status != 0 || io.Information != new IntPtr(create ? 2 : 1) || raw == IntPtr.Zero || raw == new IntPtr(-1)) throw new BrokerError(create ? "guest_fixture_mutation_uncertain" : "guest_fixture_owned_refused");
                var handle = new SafeFileHandle(raw, true); raw = IntPtr.Zero; GC.KeepAlive(parent); return handle;
            }
            finally
            {
                if (raw != IntPtr.Zero && raw != new IntPtr(-1)) Native.CloseHandle(raw);
                if (securityPin.IsAllocated) securityPin.Free();
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer); Marshal.FreeHGlobal(nameText);
            }
        }
        internal static void RenameSameParent(SafeFileHandle file, string leaf)
        {
            if (FixtureProtocol.Relative(leaf).Contains("\\") || IntPtr.Size != 4) throw new BrokerError("guest_fixture_path_rejected");
            int bytes = 16 + leaf.Length * 2; IntPtr buffer = Marshal.AllocHGlobal(bytes);
            try
            {
                for (int i = 0; i < bytes; i++) Marshal.WriteByte(buffer, i, 0);
                // Public x86 FILE_RENAME_INFORMATION: ReplaceIfExists=FALSE at0,
                // RootDirectory=NULL at4, FileNameLength at8, WCHAR basename at12.
                // NT (not Win32 CWD-relative) simple-name form renames within the
                // SOURCE'S retained parent. Never a path or destination-root form.
                Marshal.WriteInt32(buffer, 8, leaf.Length * 2);
                for (int i = 0; i < leaf.Length; i++) Marshal.WriteInt16(buffer, 12 + i * 2, (short)leaf[i]);
                Native.IoStatus io; int status = Native.NtSetInformationFile(file, out io, buffer, (uint)bytes, 10);
                if (status < 0) throw new BrokerError("guest_fixture_rename_refused");
                if (status != 0) throw new BrokerError("guest_fixture_mutation_uncertain");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        internal static void DeleteWholeObject(SafeFileHandle file)
        {
            IntPtr info = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(info, 1); // Public FILE_DISPOSITION_INFO BOOLEAN, not BOOL.
                if (!Native.SetFileInformationByHandle(file, 4, info, 1)) throw new BrokerError("guest_fixture_delete_refused");
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }
}
