using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace GuestBroker
{
    [DataContract]
    internal sealed class FixtureProcessRecord
    {
        [DataMember(IsRequired = true)] internal string Binding, RootAlias, Enrollment, Image, Slot, Instance;
        [DataMember(IsRequired = true)] internal uint Supervisor;
        [DataMember(IsRequired = true)] internal long Created, Expires;
        internal void Validate(GuestRootRecord root, string slot)
        {
            GuestProcessSupervisor.Slot(slot);
            if (Binding != root.TargetBinding || RootAlias != root.Alias || Enrollment != root.EnrollmentId || Image != root.ImageSha256 || Slot != slot || !FixtureProtocol.Hex(Instance, 32) || Supervisor == 0 || Created <= 0 || Expires <= 0) throw new BrokerError("guest_fixture_process_refused");
        }
        internal static string Context(GuestRootRecord root, string slot)
        {
            GuestProcessSupervisor.Slot(slot);
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(root.TargetBinding + "\n" + root.Alias + "\n" + root.EnrollmentId + "\n" + root.ImageSha256 + "\n" + slot))).Replace("-", "");
        }
        internal string PipeName(GuestRootRecord root) { Validate(root, Slot); return "VmwareGuestBrokerFixture-" + Context(root, Slot) + "-" + Instance; }
    }
    internal sealed partial class GuestRootStore
    {
        private string ProcessPath(GuestRootRecord root, string slot) { return Path.Combine(directory, "process-" + FixtureProcessRecord.Context(root, slot) + ".json"); }
        internal FixtureProcessRecord ReadProcess(GuestRootRecord root, string slot)
        {
            string path = ProcessPath(root, slot);
            using (var pin = PinnedDirectory.Open(directory, true))
            {
                HostPaths.CheckPrivateDirectory(directory); HostPaths.CheckPrivateFile(path);
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                {
                    HostPaths.CheckHandle(file.SafeFileHandle, path, false);
#if BROKER_TESTS
                    if (ReadSnapshotOpened != null) ReadSnapshotOpened("process", file);
#endif
                    if (file.Length < 2 || file.Length > 4096) throw new BrokerError("guest_fixture_process_refused");
                    var quotas = new System.Xml.XmlDictionaryReaderQuotas(); quotas.MaxDepth = 8; quotas.MaxStringContentLength = 128;
                    using (var reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                    {
                        var record = (FixtureProcessRecord)new DataContractJsonSerializer(typeof(FixtureProcessRecord), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 32 }).ReadObject(reader);
                        if (record == null || reader.MoveToContent() != System.Xml.XmlNodeType.None) throw new BrokerError("guest_fixture_process_refused"); record.Validate(root, slot); return record;
                    }
                }
            }
        }
        internal bool ProcessExists(GuestRootRecord root, string slot) { return File.Exists(ProcessPath(root, slot)); }
        // Caller holds the same enrollment writer lease for publication/removal.
        internal void WriteProcess(GuestRootRecord root, FixtureProcessRecord record)
        {
            record.Validate(root, record.Slot); string destination = ProcessPath(root, record.Slot), temp = Path.Combine(directory, "process.new." + Guid.NewGuid().ToString("N"));
            if (File.Exists(destination)) throw new BrokerError("guest_fixture_process_refused");
            try
            {
                using (var file = new FileStream(temp, FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, HostPaths.FileSecurity()))
                { new DataContractJsonSerializer(typeof(FixtureProcessRecord)).WriteObject(file, record); if (file.Length > 4096) throw new BrokerError("guest_fixture_process_refused"); file.Flush(true); }
                File.Move(temp, destination); HostPaths.CheckPrivateFile(destination);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        internal void RemoveProcess(GuestRootRecord root, FixtureProcessRecord record)
        {
            if (!ProcessExists(root, record.Slot)) return;
            FixtureProcessRecord current = ReadProcess(root, record.Slot);
            if (current.Instance != record.Instance || current.Supervisor != record.Supervisor || current.Created != record.Created) throw new BrokerError("guest_fixture_process_refused");
            File.Delete(ProcessPath(root, record.Slot));
        }
    }
}
