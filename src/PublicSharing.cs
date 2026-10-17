using System;
using System.IO;
using System.Runtime.Serialization;

namespace GuestBroker
{
    [DataContract]
    internal sealed class PublicShare
    {
        [DataMember(IsRequired = true)] internal string Name { get; set; }
        [DataMember(IsRequired = true)] internal string Id { get; set; }
        [DataMember(IsRequired = true)] internal ExportRoot Root { get; set; }
        internal void Validate()
        {
            if (!FixtureProtocol.Alias(Name) || !FixtureProtocol.Hex(Id, 32) || Root == null || !Target.Hex(Root.Identity, 64)) throw new BrokerError("public_share_not_approved");
            HostPaths.ApprovedRoot(Root.Path);
            if (Path.GetFileName(Root.Path) != "broker-share-" + Id) throw new BrokerError("public_share_not_approved");
        }
        internal static PublicShare Create(string parent, string name)
        {
            if (!FixtureProtocol.Alias(name)) throw new BrokerError("public_share_not_approved");
            HostPaths.ApprovedRoot(parent); if (parent.Length > 60) throw new BrokerError("public_share_not_approved");
            using (PinnedDirectory pin = PinnedDirectory.Open(parent))
            {
                string id = Guid.NewGuid().ToString("N").ToUpperInvariant(), path = Path.Combine(parent, "broker-share-" + id);
                if (!HostPaths.CreatePrivateDirectory(path)) throw new BrokerError("transfer_destination_exists");
                using (PinnedDirectory created = PinnedDirectory.Open(path))
                using (var file = new FileStream(Path.Combine(path, "public.bin"), FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()))
                    GeneratedFixture.WriteAndVerify(file, id, 1024);
                var result = new PublicShare { Name = name, Id = id, Root = ExportRoot.Capture(path) }; result.Validate(); return result;
            }
        }
        internal PinnedDirectory Open()
        {
            Validate(); PinnedDirectory pin = PinnedDirectory.Open(Root.Path);
            try
            {
                if (pin.Identity != Root.Identity) throw new BrokerError("export_root_identity_changed");
                HostPaths.CheckPrivateDirectory(Root.Path);
                // This is the NEW dedicated public fixture only, not enumeration
                // of user trees. No names or contents are exported to the result.
                string expected = Path.Combine(Root.Path, "public.bin");
                bool seen = false;
                foreach (string entry in Directory.EnumerateFileSystemEntries(Root.Path))
                { if (seen || entry != expected) throw new BrokerError("public_share_not_approved"); seen = true; }
                if (!seen) throw new BrokerError("public_share_not_approved");
                using (var file = new FileStream(expected, FileMode.Open, FileAccess.Read, FileShare.Read))
                { HostPaths.CheckHandle(file.SafeFileHandle, expected, false); HostPaths.CheckPrivateFile(expected); GeneratedFixture.Verify(file, Id, 1024); }
                return pin;
            }
            catch { pin.Dispose(); throw; }
        }
    }
    internal interface IPublicShareNative
    {
        int Count();
        bool Matches(PublicShare share, int flags);
        void Add(PublicShare share);
        void Set(PublicShare share, int flags);
        void Enable();
    }
    internal static class PublicSharing
    {
        internal static bool Command(string name) { return name == "addSharedFolder" || name == "setSharedFolderState" || name == "enableSharedFolders"; }
        internal static void Execute(VmrunRequest request, PublicShare share, IPublicShareNative native, OperationReport report)
        {
            if (!Command(request.Entry.Name) || share == null || (request.Entry.Name != "enableSharedFolders" && request.Arguments[0] != share.Name)) throw new BrokerError("public_share_not_approved");
            bool dispatched = false;
            using (share.Open())
            {
                try
                {
                    bool add = request.Entry.Name == "addSharedFolder";
                    int count = native.Count();
                    // Never globally enable/replace existing user shares. Only a
                    // sole exact owned fixture mapping can be enabled or changed.
                    if (count != (add ? 0 : 1)) throw new BrokerError("public_share_foreign_mapping");
                    if (!add && !native.Matches(share, 0) && !native.Matches(share, 4)) throw new BrokerError("public_share_foreign_mapping");
                    int desired = request.Entry.Name == "setSharedFolderState" && request.Arguments[1] == "writable" ? 4 : 0;
                    dispatched = true;
                    if (add) native.Add(share);
                    else if (request.Entry.Name == "setSharedFolderState") native.Set(share, desired);
                    else native.Enable();
                    if (native.Count() != 1 || (request.Entry.Name == "enableSharedFolders" ? !native.Matches(share, 0) && !native.Matches(share, 4) : !native.Matches(share, desired))) throw new BrokerError("public_share_foreign_mapping");
                    report.ShareName = share.Name;
                    report.Completion = request.Entry.Name == "enableSharedFolders" ? "native_completed_not_verified" : "public_share_mapping_verified";
                }
                catch (Exception) { if (dispatched) throw new BrokerError("public_share_outcome_unknown"); throw; }
            }
        }
    }
}
