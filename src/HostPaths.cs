using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static partial class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
    }
    internal sealed class PinnedDirectory : IDisposable
    {
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        internal string Path { get; private set; }
        internal string Identity { get; private set; }
        internal SafeFileHandle Handle { get { if (handles.Count == 0) throw new BrokerError("export_root_unavailable"); return handles[handles.Count - 1]; } }
        private PinnedDirectory() { }
        internal static PinnedDirectory Open(string path, bool permitLeafMetadataWrites = false)
        {
            HostPaths.ValidDirectory(path);
            var result = new PinnedDirectory { Path = path };
            try
            {
                var components = new List<string>(); string current = path;
                while (!String.IsNullOrEmpty(current)) { components.Add(current); current = System.IO.Path.GetDirectoryName(current); }
                components.Reverse();
                foreach (string component in components)
                {
                    var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                    // Default: pin ancestry against rename/delete/reparse mutation.
                    // The protected helper enrollment STORE alone permits leaf
                    // metadata writes so atomic child-file rename can work; it still
                    // denies directory deletion/rename and is not a fixture/export
                    // containment pin. Same-user/admin tampering is not isolated.
                    // FILE_LIST_DIRECTORY counts as data-read access for NT share
                    // arbitration. Metadata-only FILE_READ_ATTRIBUTES handles do
                    // NOT reliably participate in rename/delete share exclusion.
                    // No directory enumeration is actually performed.
                    uint share = permitLeafMetadataWrites && String.Equals(component, path, StringComparison.OrdinalIgnoreCase) ? 3u : 1u;
                    SafeFileHandle handle = Native.CreateFileW(component, 0x81, share, ref security, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
                    if (handle.IsInvalid) { handle.Dispose(); throw new BrokerError("export_root_unavailable"); }
                    result.handles.Add(handle);
                    HostPaths.CheckHandle(handle, component, true);
                }
                result.Identity = HostPaths.FileIdentity(result.handles[result.handles.Count - 1]);
                return result;
            }
            catch { result.Dispose(); throw; }
        }
        public void Dispose() { for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose(); handles.Clear(); }
    }
    internal static class HostPaths
    {
        internal static void ValidDirectory(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > 240 || path.Length < 3 || path[1] != ':' || path[2] != '\\' || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path.IndexOf(':', 2) >= 0 || path.IndexOfAny(new[] { '/', '*', '?', '"', '\0', '\r', '\n' }) >= 0)
                throw new BrokerError("export_root_invalid");
            foreach (char c in path) if (Char.IsControl(c)) throw new BrokerError("export_root_invalid");
            if (!String.Equals(path, System.IO.Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase) || new DriveInfo(System.IO.Path.GetPathRoot(path)).DriveType != DriveType.Fixed) throw new BrokerError("export_root_invalid");
            if (path.Length > 3) foreach (string part in path.Substring(3).Split('\\')) if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)) throw new BrokerError("export_root_invalid");
        }
        internal static void ApprovedRoot(string path)
        {
            ValidDirectory(path); if (path.Length == 3 || path.Length > 110) throw new BrokerError("export_root_invalid");
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var forbidden = new[] { Environment.GetFolderPath(Environment.SpecialFolder.Windows), System.IO.Path.Combine(home, ".ssh"), System.IO.Path.Combine(local, "Microsoft\\Credentials"), System.IO.Path.Combine(local, "Microsoft\\Vault"), System.IO.Path.Combine(local, "Microsoft\\Protect"), System.IO.Path.Combine(roaming, "Microsoft\\Credentials"), System.IO.Path.Combine(roaming, "Microsoft\\Protect"), System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft\\Crypto") };
            foreach (string secret in forbidden) if (Inside(path, secret) || Inside(secret, path)) throw new BrokerError("export_root_invalid");
            if (String.Equals(path, home, StringComparison.OrdinalIgnoreCase) || String.Equals(path, local, StringComparison.OrdinalIgnoreCase) || String.Equals(path, roaming, StringComparison.OrdinalIgnoreCase)) throw new BrokerError("export_root_invalid");
        }
        private static bool Inside(string path, string root) { return String.Equals(path, root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
        internal static void CheckHandle(SafeFileHandle handle, string expected, bool directory)
        {
            Native.FileInformation information;
            if (!Native.GetFileInformationByHandle(handle, out information) || (information.Attributes & 0x400) != 0 || ((information.Attributes & 0x10) != 0) != directory || (!directory && information.Links != 1)) throw new BrokerError("export_path_redirected");
            var path = new StringBuilder(1024); uint count = Native.GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
            if (count == 0 || count >= path.Capacity || !String.Equals(path.ToString(), @"\\?\" + expected, StringComparison.OrdinalIgnoreCase)) throw new BrokerError("export_path_redirected");
        }
        internal static string FileIdentity(SafeFileHandle handle)
        {
            Native.FileInformation info; Native.FileIdInformation id;
            if (!Native.GetFileInformationByHandle(handle, out info) || !Native.GetFileInformationByHandleEx(handle, 18, out id, 24)) throw new BrokerError("export_root_unavailable");
            return id.Volume.ToString("X16") + id.IdLow.ToString("X16") + id.IdHigh.ToString("X16") + unchecked((uint)info.Created.dwHighDateTime).ToString("X8") + unchecked((uint)info.Created.dwLowDateTime).ToString("X8");
        }
        internal static FileSecurity FileSecurity()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                var security = new FileSecurity(); security.SetOwner(identity.User); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(identity.User, FileSystemRights.FullControl, AccessControlType.Allow)); return security;
            }
        }
        internal static void CheckPrivateDirectory(string path)
        {
            var security = Directory.GetAccessControl(path);
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (!identity.User.Equals(security.GetOwner(typeof(SecurityIdentifier))) || !security.AreAccessRulesProtected) throw new BrokerError("export_acl_rejected");
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (rule.AccessControlType == AccessControlType.Allow && !identity.User.Equals(rule.IdentityReference)) throw new BrokerError("export_acl_rejected");
            }
        }
        internal static void CheckPrivateFile(string path)
        {
            var security = File.GetAccessControl(path);
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (!identity.User.Equals(security.GetOwner(typeof(SecurityIdentifier))) || !security.AreAccessRulesProtected) throw new BrokerError("export_acl_rejected");
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (rule.AccessControlType == AccessControlType.Allow && !identity.User.Equals(rule.IdentityReference)) throw new BrokerError("export_acl_rejected");
            }
        }
        internal static bool CreatePrivateDirectory(string path)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                var security = new DirectorySecurity(); security.SetOwner(identity.User); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(identity.User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                byte[] descriptor = security.GetSecurityDescriptorBinaryForm(); GCHandle pin = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
                try
                {
                    var attributes = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)), Descriptor = pin.AddrOfPinnedObject() };
                    if (Native.CreateDirectoryW(path, ref attributes)) return true;
                    if (Marshal.GetLastWin32Error() == 183) return false;
                    throw new BrokerError("export_root_unavailable");
                }
                finally { pin.Free(); }
            }
        }
    }
#if !GUEST_HELPER
    internal sealed class PrivateCapture : IDisposable
    {
        internal const long MaximumBytes = 32 * 1024 * 1024;
        private PinnedDirectory root, bucket, capture;
        private FileStream file;
        private string fileIdentity;
        internal string Id { get; private set; }
        internal string FilePath { get; private set; }
        private PrivateCapture() { }
        internal static PrivateCapture Create(Target target, ExportRoot approved)
        {
            if (approved == null) throw new BrokerError("export_root_not_approved");
            HostPaths.ApprovedRoot(approved.Path);
            var result = new PrivateCapture();
            try
            {
                result.root = PinnedDirectory.Open(approved.Path);
                if (result.root.Identity != approved.Identity) throw new BrokerError("export_root_identity_changed");
                string bucket = System.IO.Path.Combine(approved.Path, "broker-" + target.Binding);
                HostPaths.CreatePrivateDirectory(bucket); result.bucket = PinnedDirectory.Open(bucket); HostPaths.CheckPrivateDirectory(bucket);
                result.Id = Guid.NewGuid().ToString("N").ToUpperInvariant();
                string directory = System.IO.Path.Combine(bucket, "capture-" + result.Id);
                if (!HostPaths.CreatePrivateDirectory(directory)) throw new BrokerError("export_destination_exists");
                result.capture = PinnedDirectory.Open(directory); HostPaths.CheckPrivateDirectory(directory);
                result.FilePath = System.IO.Path.Combine(directory, "screen.png");
                // CreateNew: never overwrite user data. Keep the broker's empty,
                // private reservation pinned against replacement while the CLI writes.
                result.file = new FileStream(result.FilePath, FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.ReadWrite, 4096, FileOptions.None, HostPaths.FileSecurity());
                HostPaths.CheckHandle(result.file.SafeFileHandle, result.FilePath, false);
                result.fileIdentity = HostPaths.FileIdentity(result.file.SafeFileHandle);
                return result;
            }
            catch { result.Dispose(); throw; }
        }
        internal bool WithinLimit() { return file.Length <= MaximumBytes; }
        internal long ValidateCompleted()
        {
            HostPaths.CheckHandle(file.SafeFileHandle, FilePath, false);
            HostPaths.CheckPrivateFile(FilePath);
            if (fileIdentity != HostPaths.FileIdentity(file.SafeFileHandle)) throw new BrokerError("export_path_redirected");
            if (file.Length < 24 || !WithinLimit()) throw new BrokerError("private_export_invalid");
            byte[] header = new byte[24]; file.Position = 0;
            if (file.Read(header, 0, header.Length) != header.Length) throw new BrokerError("private_export_invalid");
            ValidatePngHeader(header); return file.Length;
        }
        internal static void ValidatePngHeader(byte[] header)
        {
            byte[] signature = { 137, 80, 78, 71, 13, 10, 26, 10 };
            if (header == null || header.Length != 24) throw new BrokerError("private_export_invalid");
            for (int i = 0; i < 8; i++) if (header[i] != signature[i]) throw new BrokerError("private_export_invalid");
            if (BigEndian(header, 8) != 13) throw new BrokerError("private_export_invalid");
            if (header[12] != 'I' || header[13] != 'H' || header[14] != 'D' || header[15] != 'R') throw new BrokerError("private_export_invalid");
            uint width = BigEndian(header, 16), height = BigEndian(header, 20);
            if (width == 0 || height == 0 || width > 16384 || height > 16384) throw new BrokerError("private_export_invalid");
        }
        private static uint BigEndian(byte[] bytes, int offset) { return ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3]; }
        public void Dispose()
        {
            if (file != null) { file.Dispose(); file = null; }
            if (capture != null) { capture.Dispose(); capture = null; }
            if (bucket != null) { bucket.Dispose(); bucket = null; }
            if (root != null) { root.Dispose(); root = null; }
            // No recursive cleanup, overwrite or publishing to an arbitrary path.
            // Partial files remain PRIVATE for explicit operator review/removal.
        }
    }
#endif
}
