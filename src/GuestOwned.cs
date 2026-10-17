using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    [DataContract]
    internal sealed class OwnedFixture
    {
        [DataMember(IsRequired = true)] internal string Relative { get; set; }
        [DataMember(IsRequired = true)] internal string Identity { get; set; }
        [DataMember(IsRequired = true)] internal bool Directory { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool Deleted { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string GeneratedId { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int GeneratedBytes { get; set; }
    }
    [DataContract]
    internal sealed class OwnedLedger
    {
        [DataMember(IsRequired = true)] internal int Version = 1;
        [DataMember(IsRequired = true)] internal string EnrollmentId;
        [DataMember(IsRequired = true)] internal List<OwnedFixture> Items = new List<OwnedFixture>();
        internal void Validate(GuestRootRecord root)
        {
            if (Version != 1 || EnrollmentId != root.EnrollmentId || Items == null || Items.Count > 64) throw new BrokerError("guest_fixture_owned_refused");
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (OwnedFixture item in Items)
            {
                if (item == null || !names.Add(item.Relative) || !FixtureProtocol.Hex(item.Identity, 64)) throw new BrokerError("guest_fixture_owned_refused"); FixtureProtocol.Relative(item.Relative);
                if (item.GeneratedId != null ? !FixtureProtocol.Hex(item.GeneratedId, 32) || item.GeneratedBytes < 1 || item.GeneratedBytes > GeneratedFixture.Maximum || item.Directory : item.GeneratedBytes != 0) throw new BrokerError("guest_fixture_owned_refused");
            }
        }
    }
    internal sealed class FixtureParent : IDisposable
    {
        private PinnedDirectory root, parent;
        internal string Path { get; private set; }
        internal string Leaf { get; private set; }
        internal SafeFileHandle Handle { get { return parent == null ? root.Handle : parent.Handle; } }
        private FixtureParent() { }
        internal static FixtureParent Open(GuestRootRecord record, string relative)
        {
            record.Validate(); relative = FixtureProtocol.Relative(relative);
            var pin = new FixtureParent();
            try
            {
                pin.root = PinnedDirectory.Open(record.RootPath);
                if (pin.root.Identity != record.RootIdentity) throw new BrokerError("guest_fixture_root_changed");
                string directory = System.IO.Path.GetDirectoryName(relative);
                pin.Path = String.IsNullOrEmpty(directory) ? record.RootPath : System.IO.Path.Combine(record.RootPath, directory);
                if (!String.IsNullOrEmpty(directory)) pin.parent = PinnedDirectory.Open(pin.Path);
                pin.Leaf = System.IO.Path.GetFileName(relative); return pin;
            }
            catch { pin.Dispose(); throw; }
        }
        public void Dispose() { if (parent != null) { parent.Dispose(); parent = null; } if (root != null) { root.Dispose(); root = null; } }
    }
    internal static class GuestOwned
    {
        internal static bool Operation(string value) { return value == "create-directory" || value == "create-empty-file"; }
        internal static void Apply(GuestRootStore store, GuestRootRecord record, string operation, string relative, Action beforePublication = null)
        {
            record.Validate(); FixtureProtocol.Relative(relative);
            if (!Operation(operation) || !record.OwnedMutations) throw new BrokerError("guest_fixture_owned_refused");
            bool directory = operation == "create-directory";
            using (IDisposable write = store.MutationLock())
            using (FixtureParent parent = FixtureParent.Open(record, relative))
            {
                GuestRootRecord current = store.Read(record.TargetBinding, record.Alias);
                if (current.EnrollmentId != record.EnrollmentId || current.ImageSha256 != record.ImageSha256 || current.RootIdentity != record.RootIdentity || current.RootPath != record.RootPath || !current.OwnedMutations) throw new BrokerError("guest_fixture_owned_refused");
                OwnedLedger ledger = store.ReadOwned(record);
                OwnedFixture owned = ledger.Items.Find(delegate(OwnedFixture item) { return String.Equals(item.Relative, relative, StringComparison.OrdinalIgnoreCase); });
                if (owned != null || ledger.Items.Count >= 64) throw new BrokerError("guest_fixture_create_refused");
                using (SafeFileHandle handle = OwnedNative.Create(parent.Handle, parent.Leaf, directory))
                {
                    try
                    {
                        string path = System.IO.Path.Combine(parent.Path, parent.Leaf);
                        HostPaths.CheckHandle(handle, path, directory);
                        string identity = HostPaths.FileIdentity(handle);
                        if (directory) HostPaths.CheckPrivateDirectory(path); else
                        {
                            HostPaths.CheckPrivateFile(path);
                            Native.FileInformation information;
                            if (!Native.GetFileInformationByHandle(handle, out information) || information.SizeHigh != 0 || information.SizeLow != 0) throw new BrokerError("guest_fixture_not_empty");
                        }
                        ledger.Items.Add(new OwnedFixture { Relative = relative, Identity = identity, Directory = directory });
                        if (beforePublication != null) beforePublication(); store.WriteOwned(record, ledger);
                    }
                    catch (Exception)
                    {
                        // Creation already happened. Leave any residual private object
                        // for operator review; no automatic deletion or replay.
                        throw new BrokerError("guest_fixture_mutation_uncertain");
                    }
                }
            }
        }
    }
    internal sealed partial class GuestRootStore
    {
        private string OwnedPath(GuestRootRecord root) { return Path.Combine(directory, "owned-" + root.TargetBinding + "-" + root.Alias + "-" + root.EnrollmentId + ".json"); }
        internal IDisposable MutationLock()
        {
            var lease = new OwnedLease();
            try
            {
                lease.Pin = PinnedDirectory.Open(directory, true); HostPaths.CheckPrivateDirectory(directory);
                string path = Path.Combine(directory, "enrollment.lock");
                if (File.Exists(path)) HostPaths.CheckPrivateFile(path);
                lease.File = new FileStream(path, FileMode.OpenOrCreate, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity());
                HostPaths.CheckHandle(lease.File.SafeFileHandle, path, false); return lease;
            }
            catch { lease.Dispose(); throw; }
        }
        private sealed class OwnedLease : IDisposable
        {
            internal PinnedDirectory Pin; internal FileStream File;
            public void Dispose() { if (File != null) { File.Dispose(); File = null; } if (Pin != null) { Pin.Dispose(); Pin = null; } }
        }
        internal OwnedLedger ReadOwned(GuestRootRecord root)
        {
            string path = OwnedPath(root);
            if (!File.Exists(path)) return new OwnedLedger { EnrollmentId = root.EnrollmentId };
            using (var pin = PinnedDirectory.Open(directory, true))
            {
            HostPaths.CheckPrivateDirectory(directory);
            HostPaths.CheckPrivateFile(path);
            // Protected ledger snapshot only. Mutations still take the existing
            // writer lease and re-read current metadata; old snapshot is not authority.
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            {
                HostPaths.CheckHandle(file.SafeFileHandle, path, false);
#if BROKER_TESTS
                if (ReadSnapshotOpened != null) ReadSnapshotOpened("owned", file);
#endif
                if (file.Length < 2 || file.Length > 32768) throw new BrokerError("guest_fixture_owned_refused");
                var quotas = new System.Xml.XmlDictionaryReaderQuotas(); quotas.MaxDepth = 12; quotas.MaxStringContentLength = 256; quotas.MaxArrayLength = 64;
                using (System.Xml.XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                {
                    var ledger = (OwnedLedger)new DataContractJsonSerializer(typeof(OwnedLedger)).ReadObject(reader);
                    if (ledger == null || reader.MoveToContent() != System.Xml.XmlNodeType.None) throw new BrokerError("guest_fixture_owned_refused");
                    ledger.Validate(root); return ledger;
                }
            }
            }
        }
        internal void WriteOwned(GuestRootRecord root, OwnedLedger ledger)
        {
            ledger.Validate(root); string destination = OwnedPath(root), temp = Path.Combine(directory, "owned.new." + Guid.NewGuid().ToString("N"));
            if (File.Exists(destination)) HostPaths.CheckPrivateFile(destination);
            try
            {
                using (var file = new FileStream(temp, FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, HostPaths.FileSecurity()))
                { new DataContractJsonSerializer(typeof(OwnedLedger)).WriteObject(file, ledger); if (file.Length > 32768) throw new BrokerError("guest_fixture_owned_refused"); file.Flush(true); }
                if (File.Exists(destination)) File.Replace(temp, destination, null); else File.Move(temp, destination); HostPaths.CheckPrivateFile(destination);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
    }
}
