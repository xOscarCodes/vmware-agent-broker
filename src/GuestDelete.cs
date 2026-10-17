using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static class GuestDelete
    {
        private sealed class Node : IDisposable
        {
            internal string Relative; internal SafeFileHandle File;
            public void Dispose() { if (File != null) { File.Dispose(); File = null; } }
        }
        internal static bool Operation(string value) { return value == "delete-owned-file" || value == "delete-owned-tree"; }
        internal static void Apply(GuestRootStore store, GuestRootRecord record, string relative, bool directory, Action beforeCommit = null, Action beforeIntentPublication = null, Action afterFirstDelete = null)
        {
            record.Validate(); FixtureProtocol.Relative(relative);
            if (!record.OwnedDeletes) throw new BrokerError("guest_fixture_owned_refused");
            using (store.MutationLock())
            using (FixtureParent parent = FixtureParent.Open(record, relative))
            {
                GuestRootRecord current = store.Read(record.TargetBinding, record.Alias);
                if (current.EnrollmentId != record.EnrollmentId || current.ImageSha256 != record.ImageSha256 || current.RootIdentity != record.RootIdentity || current.RootPath != record.RootPath || !current.OwnedDeletes) throw new BrokerError("guest_fixture_owned_refused");
                OwnedLedger ledger = store.ReadOwned(record); var nodes = new List<Node>(); bool attempted = false;
                try
                {
                    Preflight(parent.Handle, parent.Path, parent.Leaf, relative, directory, ledger, nodes);
                    if (beforeCommit != null) beforeCommit();
                    // Write-ahead tombstones revoke ALL old path/ID grants before
                    // any object is destroyed. Crash/partial commit cannot leave
                    // stale deletion ownership over a reused name or file ID.
                    foreach (OwnedFixture item in ledger.Items)
                        if (String.Equals(item.Relative, relative, StringComparison.OrdinalIgnoreCase) || item.Relative.StartsWith(relative + "\\", StringComparison.OrdinalIgnoreCase)) item.Deleted = true;
                    attempted = true;
                    if (beforeIntentPublication != null) beforeIntentPublication(); store.WriteOwned(record, ledger);
                    // Every physically present descendant was preflighted and pinned
                    // before the FIRST mutation. Postorder, exact retained handles;
                    // kernel refuses a nonempty directory, including a late foreign child.
                    for (int i = nodes.Count - 1; i >= 0; i--)
                    {
                        OwnedNative.DeleteWholeObject(nodes[i].File); nodes[i].Dispose();
                        if (i == nodes.Count - 1 && afterFirstDelete != null) afterFirstDelete();
                    }
                }
                catch (Exception)
                { if (attempted) throw new BrokerError("guest_fixture_mutation_uncertain"); throw; }
                finally { for (int i = nodes.Count - 1; i >= 0; i--) nodes[i].Dispose(); }
            }
        }
        private static void Preflight(SafeFileHandle parent, string parentPath, string leaf, string relative, bool directory, OwnedLedger ledger, List<Node> nodes)
        {
            FixtureProtocol.Relative(relative);
            OwnedFixture owned = ledger.Items.Find(delegate(OwnedFixture item) { return String.Equals(item.Relative, relative, StringComparison.OrdinalIgnoreCase); });
            if (owned == null || owned.Deleted || owned.Directory != directory || nodes.Count >= 64) throw new BrokerError("guest_fixture_owned_refused");
            var node = new Node { Relative = relative, File = OwnedNative.OpenOwnedObject(parent, leaf, directory) }; nodes.Add(node);
            string path = Path.Combine(parentPath, leaf); HostPaths.CheckHandle(node.File, path, directory);
            if (HostPaths.FileIdentity(node.File) != owned.Identity) throw new BrokerError("guest_fixture_owned_refused");
            if (directory) HostPaths.CheckPrivateDirectory(path); else HostPaths.CheckPrivateFile(path);
            Native.FileInformation info;
            if (!Native.GetFileInformationByHandle(node.File, out info) || (info.Attributes & 1) != 0) throw new BrokerError("guest_fixture_owned_refused");
            if (directory) GuestListing.VisitDirectory(node.File, delegate(string name, bool childDirectory)
            { Preflight(node.File, path, name, relative + "\\" + name, childDirectory, ledger, nodes); });
            // Deliberately NO primary/stream emptiness or contents check: the new
            // owner-approved whole-object test-data contract includes test streams.
        }
    }
}
