using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace GuestBroker
{
    internal sealed class CloneUuidSlot
    {
        internal long Offset;
        internal int Bytes;
        internal string Uuid;
    }
    internal static class CloneVmxIdentity
    {
        internal static string Hash(FileStream file)
        { file.Position = 0; using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", ""); }
        internal static CloneUuidSlot Slot(FileStream file)
        {
            if (file.Length < 1 || file.Length > 262144) throw new BrokerError("clone_identity_refused");
            file.Position = 0; CloneUuidSlot result = null; const string key = "uuid.bios"; int c;
            while ((c = file.ReadByte()) >= 0)
            {
                while (c == ' ' || c == '\t' || c == '\r' || c == '\n') c = file.ReadByte(); if (c < 0) break;
                bool match = true;
                for (int i = 0; i < key.Length; i++)
                { if ((c >= 'A' && c <= 'Z' ? c + 32 : c) != key[i]) { match = false; break; } c = file.ReadByte(); }
                if (match) { while (c == ' ' || c == '\t') c = file.ReadByte(); match = c == '='; }
                if (!match) { while (c >= 0 && c != '\n') c = file.ReadByte(); continue; }
                do { c = file.ReadByte(); } while (c == ' ' || c == '\t');
                if (c != '"' || result != null) throw new BrokerError("clone_identity_refused");
                long offset = file.Position; var value = new StringBuilder();
                while ((c = file.ReadByte()) != '"')
                { if (c < 0 || value.Length >= 64 || !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ' ' || c == '-')) throw new BrokerError("clone_identity_refused"); value.Append((char)c); }
                string raw = value.ToString(), uuid = raw.Replace(" ", "").Replace("-", "").ToUpperInvariant();
                if (raw.Length != 0 && !Target.Hex(uuid, 32)) throw new BrokerError("clone_identity_refused");
                result = new CloneUuidSlot { Offset = offset, Bytes = raw.Length, Uuid = uuid };
                while ((c = file.ReadByte()) >= 0 && c != '\r' && c != '\n') if (c != ' ' && c != '\t') throw new BrokerError("clone_identity_refused");
            }
            file.Position = 0; if (result == null) throw new BrokerError("clone_identity_refused"); return result;
        }
        internal static string Format(string uuid)
        {
            if (!Target.Hex(uuid, 32)) throw new BrokerError("clone_identity_refused");
            var result = new StringBuilder();
            for (int i = 0; i < 16; i++) { if (i != 0) result.Append(i == 8 ? '-' : ' '); result.Append(uuid.Substring(i * 2, 2).ToLowerInvariant()); }
            return result.ToString();
        }
        private static void Copy(FileStream input, FileStream output, long bytes)
        {
            var buffer = new byte[4096];
            try { while (bytes > 0) { int n = input.Read(buffer, 0, (int)Math.Min(buffer.Length, bytes)); if (n == 0) throw new BrokerError("clone_identity_refused"); output.Write(buffer, 0, n); bytes -= n; } }
            finally { Array.Clear(buffer, 0, buffer.Length); }
        }
        internal static string Ensure(CloneRecord record, HostMetadata store, Action<string, string> publish)
        {
            record.DemandFinalizableCopy();
            using (PinnedDirectory root = PinnedDirectory.Open(record.Root.Path, true))
            using (var file = new FileStream(record.Vmx, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            {
                if (root.Identity != record.Root.Identity) throw new BrokerError("export_root_identity_changed"); HostPaths.CheckHandle(file.SafeFileHandle, record.Vmx, false);
                CloneUuidSlot slot = Slot(file); string current = Hash(file);
                if (record.State == "initializing")
                {
                    if (slot.Uuid == record.PlannedUuid && current == record.VmxAfterHash) return slot.Uuid;
                    if (slot.Uuid.Length != 0 || current != record.VmxBeforeHash || HostPaths.FileIdentity(file.SafeFileHandle) != record.VmxBeforeIdentity) throw new BrokerError("clone_identity_refused");
                }
                else
                {
                    if (slot.Uuid.Length != 0) { if (slot.Uuid == record.SourceUuid) throw new BrokerError("owned_clone_refused"); return slot.Uuid; }
                    record.PlannedUuid = Guid.NewGuid().ToString("N").ToUpperInvariant(); if (record.PlannedUuid == record.SourceUuid) throw new BrokerError("clone_identity_refused");
                    record.VmxBeforeHash = current; record.VmxBeforeIdentity = HostPaths.FileIdentity(file.SafeFileHandle); record.State = "initializing";
                    record.Validate(store.MachineBinding); store.Write("clone-" + record.Id + ".json", record);
                }
                string temp = Path.Combine(root.Path, "uuid-" + record.PlannedUuid + ".new"); bool created = false;
                try
                {
                    using (var output = new FileStream(temp, FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, HostPaths.FileSecurity()))
                    {
                        created = true; file.Position = 0; Copy(file, output, slot.Offset);
                        byte[] uuid = Encoding.ASCII.GetBytes(Format(record.PlannedUuid)); output.Write(uuid, 0, uuid.Length);
                        file.Position = slot.Offset + slot.Bytes; Copy(file, output, file.Length - file.Position); output.Flush(true);
                        record.VmxAfterHash = Hash(output);
                    }
                    // Both before/after opaque-byte hashes are durable BEFORE
                    // atomic publication. Never parse/log/copy other VMX values
                    // as strings, and never leave a second VMX backup artifact.
                    record.Validate(store.MachineBinding); store.Write("clone-" + record.Id + ".json", record);
                    HostPaths.CheckHandle(file.SafeFileHandle, record.Vmx, false);
                    if (Hash(file) != record.VmxBeforeHash) throw new BrokerError("clone_identity_refused");
                    publish(temp, record.Vmx);
                }
                finally { if (created && File.Exists(temp)) File.Delete(temp); } // Only this operation's CreateNew temporary.
                return record.PlannedUuid;
            }
        }
    }
}
