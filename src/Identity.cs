using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace GuestBroker
{
    internal static class VmIdentity
    {
        internal static Target Capture(string name, string path)
        {
            if (!Target.ValidName(name) || !Target.ValidPath(path)) throw new BrokerError("invalid_registration");
            using (FileStream file = OpenVmx(path))
            {
                string id = FileId(file);
                return new Target { Name = name, Vmx = path, Uuid = ReadUuid(file), FileIdentity = id, Generation = Guid.NewGuid().ToString("N").ToUpperInvariant(), IdentityMode = "path-uuid-v1", ObservedFileIdentity = id, IdentityRevision = 1 };
            }
        }
        internal static FileStream Open(Target target)
        {
            target.Validate();
            FileStream file = OpenLogical(target);
            try
            {
                if (target.IdentityMode == null && FileId(file) != target.FileIdentity) throw new BrokerError("vm_identity_changed_reenroll_required");
                return file;
            }
            catch { file.Dispose(); throw; }
        }
        internal static FileStream OpenLogical(Target target)
        {
            target.Validate(); FileStream file = OpenVmx(target.Vmx);
            try { FileId(file); if (ReadUuid(file) != target.Uuid) throw new BrokerError("vm_identity_changed_reenroll_required"); return file; }
            catch { file.Dispose(); throw; }
        }
        private sealed class PinnedVmxStream : FileStream
        {
            private PinnedDirectory parent;
            internal PinnedVmxStream(string path, PinnedDirectory pin) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read) { parent = pin; }
            protected override void Dispose(bool disposing) { try { base.Dispose(disposing); } finally { if (parent != null) { parent.Dispose(); parent = null; } } }
        }
        private static FileStream OpenVmx(string path)
        {
            if (!Target.ValidPath(path)) throw new BrokerError("invalid_registration");
            PinnedDirectory parent = PinnedDirectory.Open(Path.GetDirectoryName(path)); FileStream file = null;
            try { Policy.NoReparse(path); file = new PinnedVmxStream(path, parent); HostPaths.CheckHandle(file.SafeFileHandle, path, false); return file; }
            catch { if (file != null) file.Dispose(); else parent.Dispose(); throw; }
        }
        internal static string FileId(FileStream file)
        {
            Native.FileInformation info;
            Native.FileIdInformation identity;
            if (!Native.GetFileInformationByHandle(file.SafeFileHandle, out info)) throw new BrokerError("vm_identity_unavailable");
            // FILE_ID_INFO uses 128-bit IDs (the older 64-bit index is not unique
            // on ReFS). No fallback to weaker/missing identity data.
            if (!Native.GetFileInformationByHandleEx(file.SafeFileHandle, 18, out identity, 24)) throw new BrokerError("vm_identity_unavailable");
            return identity.Volume.ToString("X16") + identity.IdLow.ToString("X16") + identity.IdHigh.ToString("X16") +
                unchecked((uint)info.Created.dwHighDateTime).ToString("X8") + unchecked((uint)info.Created.dwLowDateTime).ToString("X8");
        }
        internal static string ReadUuid(Stream file)
        {
            // Only uuid.bios is interpreted. Other VMX keys/values are skipped
            // byte by byte, never materialized as strings, parsed, or reported.
            if (file.Length < 1 || file.Length > 4 * 1024 * 1024) throw new BrokerError("vm_identity_unavailable");
            file.Position = 0;
            const string key = "uuid.bios";
            string result = null;
            int c;
            while ((c = file.ReadByte()) >= 0)
            {
                while (c == ' ' || c == '\t' || c == '\r' || c == '\n') c = file.ReadByte();
                if (c < 0) break;
                bool matches = true;
                for (int i = 0; i < key.Length; i++)
                {
                    int lower = c >= 'A' && c <= 'Z' ? c + 32 : c;
                    if (lower != key[i]) { matches = false; break; }
                    c = file.ReadByte();
                }
                if (matches)
                {
                    while (c == ' ' || c == '\t') c = file.ReadByte();
                    matches = c == '=';
                }
                if (matches)
                {
                    var value = new StringBuilder(64);
                    while ((c = file.ReadByte()) >= 0 && c != '\n' && c != '\r')
                    {
                        if (value.Length >= 128 || c > 127) throw new BrokerError("vm_identity_unavailable");
                        value.Append((char)c);
                    }
                    string quoted = value.ToString().Trim();
                    if (quoted.Length < 2 || quoted[0] != '"' || quoted[quoted.Length - 1] != '"') throw new BrokerError("vm_identity_unavailable");
                    string uuid = quoted.Substring(1, quoted.Length - 2).Replace(" ", "").Replace("-", "").ToUpperInvariant();
                    if (!Target.Hex(uuid, 32) || result != null) throw new BrokerError("vm_identity_unavailable");
                    result = uuid;
                }
                else while (c >= 0 && c != '\n') c = file.ReadByte();
            }
            if (result == null) throw new BrokerError("vm_identity_unavailable");
            file.Position = 0;
            return result;
        }
    }
}
