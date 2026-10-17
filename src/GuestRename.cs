using System;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static class GuestRename
    {
        internal static string Destination(string relative, string leaf)
        {
            FixtureProtocol.Relative(relative);
            if (FixtureProtocol.Relative(leaf).Contains("\\")) throw new BrokerError("guest_fixture_path_rejected");
            string parent = Path.GetDirectoryName(relative);
            string result = String.IsNullOrEmpty(parent) ? leaf : Path.Combine(parent, leaf);
            FixtureProtocol.Relative(result);
            if (String.Equals(relative, result, StringComparison.OrdinalIgnoreCase)) throw new BrokerError("guest_fixture_rename_refused");
            return result;
        }
        internal static void Apply(GuestRootStore store, GuestRootRecord record, string relative, string leaf, Action beforePublication = null)
        {
            record.Validate(); string destination = Destination(relative, leaf);
            if (!record.OwnedRenames) throw new BrokerError("guest_fixture_owned_refused");
            using (store.MutationLock())
            using (FixtureParent parent = FixtureParent.Open(record, relative))
            {
                GuestRootRecord current = store.Read(record.TargetBinding, record.Alias);
                if (current.EnrollmentId != record.EnrollmentId || current.ImageSha256 != record.ImageSha256 || current.RootIdentity != record.RootIdentity || current.RootPath != record.RootPath || !current.OwnedRenames) throw new BrokerError("guest_fixture_owned_refused");
                OwnedLedger ledger = store.ReadOwned(record);
                OwnedFixture owned = ledger.Items.Find(delegate(OwnedFixture item) { return String.Equals(item.Relative, relative, StringComparison.OrdinalIgnoreCase); });
                if (owned == null || owned.Directory || owned.Deleted || ledger.Items.Exists(delegate(OwnedFixture item) { return String.Equals(item.Relative, destination, StringComparison.OrdinalIgnoreCase); })) throw new BrokerError("guest_fixture_owned_refused");
                using (SafeFileHandle file = OwnedNative.OpenOwnedFile(parent.Handle, parent.Leaf))
                {
                    string source = Path.Combine(parent.Path, parent.Leaf);
                    HostPaths.CheckHandle(file, source, false); HostPaths.CheckPrivateFile(source);
                    if (HostPaths.FileIdentity(file) != owned.Identity) throw new BrokerError("guest_fixture_owned_refused");
                    Native.FileInformation information;
                    if (!Native.GetFileInformationByHandle(file, out information) || information.SizeHigh != 0 || information.SizeLow != 0) throw new BrokerError("guest_fixture_not_empty");
                    // Main-stream zero is only a scope restriction, NOT proof of
                    // all-stream emptiness. Rename keeps the entire owned object;
                    // no stream is opened, read, copied, truncated or deleted.
                    OwnedNative.RenameSameParent(file, leaf);
                    try
                    {
                        string target = Path.Combine(parent.Path, leaf);
                        HostPaths.CheckHandle(file, target, false); HostPaths.CheckPrivateFile(target);
                        if (HostPaths.FileIdentity(file) != owned.Identity) throw new BrokerError("guest_fixture_owned_refused");
                        owned.Relative = destination;
                        if (beforePublication != null) beforePublication(); store.WriteOwned(record, ledger);
                    }
                    catch (Exception) { throw new BrokerError("guest_fixture_mutation_uncertain"); }
                    // Never roll back/replay: post-effect publication is not a
                    // filesystem transaction. A stale ledger grants no new object.
                }
            }
        }
    }
}
