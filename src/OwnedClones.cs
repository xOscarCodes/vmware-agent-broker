using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class CloneDisk
    {
        [DataMember(IsRequired = true)] internal string Name;
        [DataMember(IsRequired = true)] internal string Identity;
    }
    [DataContract]
    internal sealed class CloneRecord
    {
        [DataMember(IsRequired = true)] internal string Machine, Id, SourceBinding, SourceUuid, State;
        [DataMember(IsRequired = true)] internal ExportRoot Root;
        [DataMember(EmitDefaultValue = false)] internal string Uuid, RegisteredBinding;
        [DataMember(EmitDefaultValue = false)] internal List<CloneDisk> Disks;
        [DataMember(EmitDefaultValue = false)] internal List<CloneDisk> Files;
        [DataMember(EmitDefaultValue = false)] internal string CopyProof;
        // Recognize the withdrawn15.3 fields only to reject them, never silently
        // deserialize a reviewed assertion as a native-completion receipt.
        [DataMember(Name = "ReviewedSourceHash", EmitDefaultValue = false)] private string rejectedLegacySourceHash = null;
        [DataMember(Name = "ReviewOriginBroker", EmitDefaultValue = false)] private string rejectedLegacyOriginBroker = null;
        [DataMember(Name = "ReviewedSourceBytes", EmitDefaultValue = false)] private long? rejectedLegacySourceBytes = null;
        [DataMember(EmitDefaultValue = false)] internal string PlannedUuid, VmxBeforeHash, VmxAfterHash, VmxBeforeIdentity;
        internal string Vmx { get { return Path.Combine(Root.Path, "machine.vmx"); } }
        internal void Validate(string machine)
        {
            if (Machine != machine || !Target.Hex(Id, 32) || !Target.Hex(SourceBinding, 64) || !Target.Hex(SourceUuid, 32) || Root == null || !Target.Hex(Root.Identity, 64) || Path.GetFileName(Root.Path) != "clone-" + Id || Array.IndexOf(new[] { "prepared", "copied", "initializing", "ready", "deleting", "deleted" }, State) < 0) throw new BrokerError("owned_clone_refused");
            HostPaths.ApprovedRoot(Root.Path);
            if ((State == "ready" || State == "deleting" || State == "deleted") && (!Target.Hex(Uuid, 32) || Uuid == SourceUuid || Disks == null || Disks.Count == 0 || Disks.Count > 128 || Files == null || Files.Count == 0 || Files.Count > 160)) throw new BrokerError("owned_clone_refused");
            if (CopyProof != null && CopyProof != "native_job_success_v1" || (State == "copied" || State == "initializing") && CopyProof != "native_job_success_v1" || State == "prepared" && CopyProof != null) throw new BrokerError("owned_clone_refused");
            if (rejectedLegacySourceHash != null || rejectedLegacyOriginBroker != null || rejectedLegacySourceBytes.HasValue) throw new BrokerError("owned_clone_refused");
            if (PlannedUuid != null ? !Target.Hex(PlannedUuid, 32) || PlannedUuid == SourceUuid || !Target.Hex(VmxBeforeHash, 64) || !Target.Hex(VmxBeforeIdentity, 64) || VmxAfterHash != null && !Target.Hex(VmxAfterHash, 64) : VmxBeforeHash != null || VmxAfterHash != null || VmxBeforeIdentity != null || State == "initializing") throw new BrokerError("owned_clone_refused");
            if ((State == "prepared" || State == "copied" || State == "initializing") && RegisteredBinding != null) throw new BrokerError("owned_clone_refused");
            if (RegisteredBinding != null && (!Target.Hex(RegisteredBinding, 64) || RegisteredBinding == SourceBinding)) throw new BrokerError("owned_clone_refused");
            if (Disks != null)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (CloneDisk disk in Disks) if (disk == null || !CloneDisks.LocalName(disk.Name) || !Target.Hex(disk.Identity, 64) || !names.Add(disk.Name)) throw new BrokerError("owned_clone_refused");
            }
            if (Files != null)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (CloneDisk file in Files) if (file == null || !CloneDisks.FileName(file.Name) || !Target.Hex(file.Identity, 64) || !names.Add(file.Name)) throw new BrokerError("owned_clone_refused");
            }
        }
        internal void DemandFinalizableCopy()
        {
            if ((State != "copied" && State != "initializing") || CopyProof != "native_job_success_v1") throw new BrokerError("clone_copy_proof_required");
        }
    }
    internal static class CloneDisks
    {
        internal static bool FileName(string name) { return name != null && name.Length <= 100 && Regex.IsMatch(name, @"^[A-Za-z0-9][A-Za-z0-9 _.-]*$") && !name.Contains(".."); }
        internal static bool LocalName(string name)
        { return name != null && name.Length <= 100 && Regex.IsMatch(name, @"^[A-Za-z0-9][A-Za-z0-9 _.-]*\.vmdk$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) && !name.Contains(".."); }
        internal static string Descriptor(FileStream file)
        {
            var header = new byte[512]; int n = file.Read(header, 0, header.Length);
            long offset = 0; int length;
            if (n >= 44 && BitConverter.ToUInt32(header, 0) == 0x564D444B)
            {
                ulong sector = BitConverter.ToUInt64(header, 28), count = BitConverter.ToUInt64(header, 36);
                if (sector == 0 || count == 0 || count > 128 || sector > (ulong)file.Length / 512 || count > (ulong)file.Length / 512 - sector) throw new BrokerError("owned_clone_backing_refused");
                offset = (long)(sector * 512); length = (int)(count * 512);
            }
            else { if (file.Length < 1 || file.Length > 65536 || header[0] != '#') throw new BrokerError("owned_clone_backing_refused"); length = (int)file.Length; }
            var bytes = new byte[length]; file.Position = offset; int read = 0;
            while (read < length) { int amount = file.Read(bytes, read, length - read); if (amount == 0) throw new BrokerError("owned_clone_backing_refused"); read += amount; }
            try { string result = new UTF8Encoding(false, true).GetString(bytes).TrimEnd('\0'); if (result.Contains("\0")) throw new BrokerError("owned_clone_backing_refused"); return result; }
            catch (ArgumentException) { throw new BrokerError("owned_clone_backing_refused"); }
        }
        internal static List<string> Extents(string descriptor)
        {
            bool parent = false, kind = false; var names = new List<string>();
            foreach (string raw in descriptor.Replace("\r\n", "\n").Split('\n'))
            {
                string line = raw.Trim(); if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                if (Regex.IsMatch(line, @"^parentCID\s*=", RegexOptions.IgnoreCase))
                { if (parent || !Regex.IsMatch(line, @"^parentCID\s*=\s*ffffffff$", RegexOptions.IgnoreCase)) throw new BrokerError("owned_clone_backing_refused"); parent = true; }
                else if (Regex.IsMatch(line, @"^parentFileNameHint\s*=", RegexOptions.IgnoreCase)) throw new BrokerError("owned_clone_backing_refused");
                else if (Regex.IsMatch(line, @"^createType\s*=", RegexOptions.IgnoreCase))
                { if (kind || !Regex.IsMatch(line, "^createType\\s*=\\s*\"(monolithicSparse|twoGbMaxExtentSparse|monolithicFlat|twoGbMaxExtentFlat|streamOptimized)\"$")) throw new BrokerError("owned_clone_backing_refused"); kind = true; }
                else if (Regex.IsMatch(line, @"^(RW|RDONLY|NOACCESS)\s", RegexOptions.IgnoreCase))
                {
                    Match extent = Regex.Match(line, "^RW [1-9][0-9]{0,18} (SPARSE|FLAT) \"([^\"]+)\"(?: (?:0|[1-9][0-9]{0,18}))?$");
                    if (!extent.Success || !LocalName(extent.Groups[2].Value) || names.Count >= 128) throw new BrokerError("owned_clone_backing_refused"); names.Add(extent.Groups[2].Value);
                }
            }
            if (!parent || !kind || names.Count == 0) throw new BrokerError("owned_clone_backing_refused"); return names;
        }
        internal static List<CloneDisk> Inspect(string vmx)
        {
            string root = Path.GetDirectoryName(vmx); var descriptors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var file = Policy.OpenPinned(vmx))
            {
                if (file.Length > 262144) throw new BrokerError("owned_clone_backing_refused");
                foreach (string key in new[] { "nvram", "extendedConfigFile" })
                {
                    string value = DeviceBinding.Field(file, key, true); if (String.IsNullOrEmpty(value)) continue;
                    // Native Delete may remove associated configuration files as
                    // well as disk data. A full clone must not retain a source
                    // NVRAM/VMXF path, even if every VMDK itself is local.
                    string name = Path.GetFileName(value);
                    if (!FileName(name) || value != name && !String.Equals(value, Path.Combine(root, name), StringComparison.OrdinalIgnoreCase)) throw new BrokerError("owned_clone_backing_refused");
                }
                string working = DeviceBinding.Field(file, "workingDir", true), checkpoint = DeviceBinding.Field(file, "checkpoint.vmState", true);
                if (!String.IsNullOrEmpty(working) && working != "." && !String.Equals(working, root, StringComparison.OrdinalIgnoreCase) || !String.IsNullOrEmpty(checkpoint)) throw new BrokerError("owned_clone_backing_refused");
                foreach (string bus in new[] { "sata", "scsi", "ide", "nvme" })
                    for (int controller = 0; controller < 4; controller++) for (int slot = 0; slot < 16; slot++)
                    {
                        string id = bus + controller + ":" + slot, name = DeviceBinding.Field(file, id + ".fileName", true);
                        if (name == null) continue;
                        string type = DeviceBinding.Field(file, id + ".deviceType", true);
                        if (type == "cdrom-image" || type == "atapi-cdrom") continue; // Optical media is not a disk-file delete grant.
                        if (!LocalName(name)) throw new BrokerError("owned_clone_backing_refused"); descriptors.Add(name);
                    }
            }
            if (descriptors.Count == 0 || descriptors.Count > 16) throw new BrokerError("owned_clone_backing_refused");
            var names = new HashSet<string>(descriptors, StringComparer.OrdinalIgnoreCase);
            foreach (string name in descriptors) using (var disk = Policy.OpenPinned(Path.Combine(root, name)))
            { HostPaths.CheckHandle(disk.SafeFileHandle, Path.Combine(root, name), false); foreach (string extent in Extents(Descriptor(disk))) names.Add(extent); }
            if (names.Count > 128) throw new BrokerError("owned_clone_backing_refused");
            var result = new List<CloneDisk>();
            foreach (string name in names) using (var disk = Policy.OpenPinned(Path.Combine(root, name)))
            { HostPaths.CheckHandle(disk.SafeFileHandle, Path.Combine(root, name), false); result.Add(new CloneDisk { Name = name, Identity = HostPaths.FileIdentity(disk.SafeFileHandle) }); }
            result.Sort(delegate(CloneDisk a, CloneDisk b) { return StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name); }); return result;
        }
    }
    internal interface ICloneNative { int Power(); void Clone(string destination); void Delete(); }
    internal static partial class OwnedClones
    {
        internal static void Stopped(int power) { if ((power & 2) == 0 || (power & (1 | 4 | 8 | 16 | 32 | 128 | 512 | 2048)) != 0) throw new BrokerError("clone_power_state_refused"); }
        private static bool Inside(string a, string b) { return a.Equals(b, StringComparison.OrdinalIgnoreCase) || a.StartsWith(b.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
        internal static void Parent(Target source, ExportRoot parent)
        {
            if (source.Name == "SAFE-DC" || parent == null) throw new BrokerError("owned_clone_refused"); HostPaths.ApprovedRoot(parent.Path);
            if (parent.Path.Length > 70 || Inside(parent.Path, Path.GetDirectoryName(source.Vmx)) || Inside(Path.GetDirectoryName(source.Vmx), parent.Path)) throw new BrokerError("owned_clone_refused");
        }
        internal static CloneRecord Read(HostMetadata store, string id)
        {
            if (!Target.Hex(id, 32)) throw new BrokerError("owned_clone_refused"); CloneRecord record = store.Read<CloneRecord>("clone-" + id + ".json");
            if (record == null || record.Id != id) throw new BrokerError("owned_clone_refused"); record.Validate(store.MachineBinding); return record;
        }
        internal static void Create(Target source, ExportRoot parent, VmrunRequest request, HostMetadata store, ICloneNative native, OperationReport result)
        {
            Parent(source, parent); Stopped(native.Power());
            using (store.Lock()) using (PinnedDirectory root = PinnedDirectory.Open(parent.Path))
            {
                if (root.Identity != parent.Identity) throw new BrokerError("export_root_identity_changed");
                string path = Path.Combine(parent.Path, "clone-" + request.GeneratedId);
                if (!HostPaths.CreatePrivateDirectory(path)) throw new BrokerError("transfer_destination_exists");
                var record = new CloneRecord { Machine = store.MachineBinding, Id = request.GeneratedId, SourceBinding = source.Binding, SourceUuid = source.Uuid, State = "prepared", Root = ExportRoot.Capture(path) };
                record.Validate(store.MachineBinding); store.Write("clone-" + record.Id + ".json", record);
                try
                {
                    native.Clone(record.Vmx);
                    Diagnostics.At(Stage.CloneNativeComplete);
                    // Persist observed native completion/path check BEFORE any
                    // BIOS UUID parsing. Empty deferred UUID is identity work,
                    // not permission to repeat an already completed full copy.
                    record.State = "copied"; record.CopyProof = "native_job_success_v1";
                    record.Validate(store.MachineBinding); store.Write("clone-" + record.Id + ".json", record);
                    FinishIdentity(record, store, new Target[0], delegate(string temp, string destination) { File.Replace(temp, destination, null); });
                    result.CloneId = record.Id; result.Completion = "owned_full_clone_created";
                }
                catch (Exception) { Diagnostics.Fault(); throw new BrokerError("owned_clone_outcome_unknown"); }
            }
        }
        internal static void ValidateCurrent(CloneRecord record, Target target)
        {
            if (record.State != "ready" || target.Name == "SAFE-DC" || record.Uuid != target.Uuid || record.RegisteredBinding != target.Binding || record.SourceBinding == target.Binding || record.SourceUuid == target.Uuid || record.Vmx != target.Vmx) throw new BrokerError("owned_clone_refused");
            using (VmIdentity.Open(target)) { }
            using (PinnedDirectory root = PinnedDirectory.Open(record.Root.Path))
            {
                if (root.Identity != record.Root.Identity) throw new BrokerError("export_root_identity_changed");
                List<CloneDisk> current = CloneDisks.Inspect(target.Vmx);
                if (current.Count != record.Disks.Count) throw new BrokerError("owned_clone_backing_refused");
                for (int i = 0; i < current.Count; i++) if (current[i].Name != record.Disks[i].Name || current[i].Identity != record.Disks[i].Identity) throw new BrokerError("owned_clone_backing_refused");
                int entries = 0;
                foreach (string entry in Directory.EnumerateFileSystemEntries(root.Path))
                {
                    if (++entries > 176) throw new BrokerError("owned_clone_refused"); string name = Path.GetFileName(entry);
                    if ((File.GetAttributes(entry) & FileAttributes.Directory) != 0)
                    {
                        // Native OpenVM may add its own lock directories. No
                        // traversal/adoption of other host trees is permitted.
                        if (name != "machine.vmx.lck" && !record.Disks.Exists(delegate(CloneDisk disk) { return name == disk.Name + ".lck"; })) throw new BrokerError("owned_clone_refused");
                        Policy.NoReparse(entry); continue;
                    }
                    CloneDisk owned = record.Files.Find(delegate(CloneDisk file) { return file.Name == name; });
                    if (owned == null && !Regex.IsMatch(name, @"^vmware(-[0-9]+)?\.log$")) throw new BrokerError("owned_clone_refused");
                    using (var pin = Policy.OpenPinned(entry))
                    {
                        HostPaths.CheckHandle(pin.SafeFileHandle, entry, false);
                        if (owned != null && name != "machine.vmx" && owned.Identity != HostPaths.FileIdentity(pin.SafeFileHandle)) throw new BrokerError("owned_clone_refused");
                    }
                }
            }
        }
        internal static void Delete(Target target, string id, HostMetadata store, ICloneNative native, OperationReport result)
        {
            Stopped(native.Power());
            using (store.Lock())
            {
                CloneRecord record = Read(store, id); ValidateCurrent(record, target);
                record.State = "deleting"; store.Write("clone-" + id + ".json", record); // Durable intent; unknown may NOT replay.
                try
                {
                    native.Delete();
                    if (File.Exists(target.Vmx)) throw new BrokerError("owned_clone_refused");
                    foreach (CloneDisk disk in record.Disks) if (File.Exists(Path.Combine(record.Root.Path, disk.Name))) throw new BrokerError("owned_clone_refused");
                    record.State = "deleted"; store.Write("clone-" + id + ".json", record);
                    result.CloneId = id; result.Completion = "owned_clone_deleted";
                }
                catch (Exception) { Diagnostics.Fault(); throw new BrokerError("owned_clone_outcome_unknown"); }
            }
        }
    }
}
