using System;
using System.Collections.Generic;
using System.IO;

namespace GuestBroker
{
    internal static partial class OwnedClones
    {
        private static List<CloneDisk> Files(CloneRecord record)
        {
            var result = new List<CloneDisk>();
            foreach (string path in Directory.EnumerateFileSystemEntries(record.Root.Path))
            {
                string name = Path.GetFileName(path);
                if (result.Count >= 160 || !CloneDisks.FileName(name) || (File.GetAttributes(path) & FileAttributes.Directory) != 0 || !(name == "machine.vmx" || name == "machine.nvram" || name == "machine.vmsd" || name == "machine.vmxf" || name == "vmware.log" || System.Text.RegularExpressions.Regex.IsMatch(name, @"^vmware-[0-9]+\.log$") || record.Disks.Exists(delegate(CloneDisk disk) { return disk.Name == name; }))) throw new BrokerError("owned_clone_refused");
                using (var file = Policy.OpenPinned(path)) { HostPaths.CheckHandle(file.SafeFileHandle, path, false); result.Add(new CloneDisk { Name = name, Identity = HostPaths.FileIdentity(file.SafeFileHandle) }); }
            }
            using (var vmx = Policy.OpenPinned(record.Vmx))
                foreach (string key in new[] { "nvram", "extendedConfigFile" })
                {
                    string value = DeviceBinding.Field(vmx, key, true);
                    if (!String.IsNullOrEmpty(value) && !result.Exists(delegate(CloneDisk item) { return String.Equals(item.Name, Path.GetFileName(value), StringComparison.OrdinalIgnoreCase); })) throw new BrokerError("owned_clone_refused");
                }
            return result;
        }
        private static void SameDisks(List<CloneDisk> expected, List<CloneDisk> current)
        {
            if (expected == null || current.Count != expected.Count) throw new BrokerError("owned_clone_backing_refused");
            for (int i = 0; i < current.Count; i++) if (current[i].Name != expected[i].Name || current[i].Identity != expected[i].Identity) throw new BrokerError("owned_clone_backing_refused");
        }
        private static void NoRegistration(CloneRecord record, IList<Target> registered)
        {
            if (record.RegisteredBinding != null) throw new BrokerError("owned_clone_refused");
            foreach (Target target in registered)
                if (Inside(target.Vmx, record.Root.Path) || record.PlannedUuid != null && target.Uuid == record.PlannedUuid || record.Uuid != null && target.Uuid == record.Uuid) throw new BrokerError("owned_clone_refused");
        }
        private static void FinishIdentity(CloneRecord record, HostMetadata store, IList<Target> registered, Action<string, string> publish)
        {
            record.DemandFinalizableCopy();
            NoRegistration(record, registered);
            using (PinnedDirectory root = PinnedDirectory.Open(record.Root.Path, true))
            {
                if (root.Identity != record.Root.Identity) throw new BrokerError("export_root_identity_changed"); HostPaths.CheckPrivateDirectory(root.Path);
                List<CloneDisk> disks = CloneDisks.Inspect(record.Vmx);
                if (record.Disks != null) SameDisks(record.Disks, disks); else record.Disks = disks;
                List<CloneDisk> files = Files(record);
                if (record.Files != null)
                    foreach (CloneDisk expected in record.Files)
                        if (expected.Name != "machine.vmx" && !files.Exists(delegate(CloneDisk item) { return item.Name == expected.Name && item.Identity == expected.Identity; })) throw new BrokerError("owned_clone_refused");
                record.Files = files;
                var pins = new List<FileStream>();
                try
                {
                    // Retain clone files against active copy/VM writes. Do not
                    // pin or inspect the now-running original source disk/config.
                    foreach (CloneDisk item in files) if (item.Name != "machine.vmx")
                    {
                        string path = Path.Combine(root.Path, item.Name); FileStream pin = Policy.OpenPinned(path); pins.Add(pin);
                        HostPaths.CheckHandle(pin.SafeFileHandle, path, false); if (HostPaths.FileIdentity(pin.SafeFileHandle) != item.Identity) throw new BrokerError("owned_clone_refused");
                    }
                    FinishPinnedIdentity(record, store, registered, publish);
                }
                finally { foreach (FileStream pin in pins) pin.Dispose(); }
            }
        }
        private static void FinishPinnedIdentity(CloneRecord record, HostMetadata store, IList<Target> registered, Action<string, string> publish)
        {
                Diagnostics.At(Stage.CloneIdentity); string uuid = CloneVmxIdentity.Ensure(record, store, publish);
                if (uuid == record.SourceUuid) throw new BrokerError("owned_clone_refused");
                foreach (Target target in registered) if (target.Uuid == uuid) throw new BrokerError("owned_clone_refused");
                Target captured = VmIdentity.Capture("OwnedClone", record.Vmx);
                if (captured.Uuid != uuid) throw new BrokerError("clone_identity_refused");
                record.Uuid = uuid; record.Files = Files(record); record.State = "ready";
                record.Validate(store.MachineBinding); store.Write("clone-" + record.Id + ".json", record);
        }
        internal static CloneRecord FinalizePrepared(Target source, ExportRoot parent, string id, IList<Target> registered, HostMetadata store, Action<string, string> publish)
        {
            Parent(source, parent);
            using (store.Lock()) using (var deadline = new Deadline()) using (PinnedDirectory pinnedParent = PinnedDirectory.Open(parent.Path))
            {
                if (pinnedParent.Identity != parent.Identity) throw new BrokerError("export_root_identity_changed");
                CloneRecord record = Read(store, id);
                if (record.SourceBinding != source.Binding || record.SourceUuid != source.Uuid || record.Root.Path != Path.Combine(parent.Path, "clone-" + id)) throw new BrokerError("owned_clone_refused");
                record.DemandFinalizableCopy(); // Every unproved prepared ID, including F200, refuses.
                NoRegistration(record, registered);
                try { FinishIdentity(record, store, registered, publish); return record; }
                catch (Exception) { Diagnostics.Fault(); throw new BrokerError("clone_identity_outcome_unknown"); }
            }
        }
    }
}
