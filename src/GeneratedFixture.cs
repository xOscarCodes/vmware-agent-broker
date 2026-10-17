using System;
using System.Globalization;
using System.IO;

namespace GuestBroker
{
    // Generated PUBLIC test bytes only. Never imports caller data or regenerates
    // data while claiming it was transferred across a VM boundary.
    internal static class GeneratedFixture
    {
        internal const int Maximum = 1024 * 1024;
        internal static int Size(string text)
        {
            int size;
            if (!Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out size) || size < 1 || size > Maximum || size.ToString(CultureInfo.InvariantCulture) != text) throw new BrokerError("guest_fixture_generated_refused"); return size;
        }
        private static byte[] Seed(string id)
        {
            if (!FixtureProtocol.Hex(id, 32)) throw new BrokerError("guest_fixture_generated_refused");
            var seed = new byte[16]; for (int i = 0; i < seed.Length; i++) seed[i] = Convert.ToByte(id.Substring(i * 2, 2), 16); return seed;
        }
        private static void Fill(byte[] buffer, int count, int offset, byte[] seed)
        { for (int i = 0; i < count; i++) { int position = offset + i; buffer[i] = (byte)(((position * 31) ^ seed[position % seed.Length]) & 255); } }
        internal static void WriteAndVerify(FileStream file, string id, int size)
        {
            if (size < 1 || size > Maximum || file.Length != 0) throw new BrokerError("guest_fixture_generated_refused");
            byte[] seed = Seed(id), buffer = new byte[4096];
            try
            {
                for (int offset = 0; offset < size; offset += buffer.Length)
                { int count = Math.Min(buffer.Length, size - offset); Fill(buffer, count, offset, seed); file.Write(buffer, 0, count); }
                file.Flush(true); Verify(file, id, size);
            }
            finally { Array.Clear(seed, 0, seed.Length); Array.Clear(buffer, 0, buffer.Length); }
        }
        internal static void Verify(FileStream file, string id, int size)
        {
            if (size < 1 || size > Maximum || file.Length != size) throw new BrokerError("guest_fixture_generated_refused");
            byte[] seed = Seed(id), buffer = new byte[4096], expected = new byte[4096];
            try
            {
                file.Position = 0;
                for (int offset = 0; offset < size; offset += buffer.Length)
                {
                    int count = Math.Min(buffer.Length, size - offset), read = 0; Fill(expected, count, offset, seed);
                    while (read < count) { int n = file.Read(buffer, read, count - read); if (n == 0) throw new BrokerError("guest_fixture_generated_refused"); read += n; }
                    for (int i = 0; i < count; i++) if (buffer[i] != expected[i]) throw new BrokerError("guest_fixture_generated_refused");
                }
            }
            finally { Array.Clear(seed, 0, seed.Length); Array.Clear(buffer, 0, buffer.Length); Array.Clear(expected, 0, expected.Length); }
        }
        internal static void Create(GuestRootStore store, GuestRootRecord root, string relative, string sizeText, string id)
        {
            root.Validate(); FixtureProtocol.Relative(relative); int size = Size(sizeText); if (!FixtureProtocol.Hex(id, 32)) throw new BrokerError("guest_fixture_generated_refused");
            if (!root.GeneratedFixtures) throw new BrokerError("guest_fixture_owned_refused");
            using (store.MutationLock())
            using (FixtureParent parent = FixtureParent.Open(root, relative))
            {
                GuestRootRecord now = store.Read(root.TargetBinding, root.Alias);
                if (!now.GeneratedFixtures || now.EnrollmentId != root.EnrollmentId || now.ImageSha256 != root.ImageSha256 || now.RootIdentity != root.RootIdentity || now.RootPath != root.RootPath) throw new BrokerError("guest_fixture_owned_refused");
                OwnedLedger ledger = store.ReadOwned(root);
                if (ledger.Items.Count >= 64 || ledger.Items.Exists(delegate(OwnedFixture item) { return String.Equals(item.Relative, relative, StringComparison.OrdinalIgnoreCase); })) throw new BrokerError("guest_fixture_create_refused");
                using (var handle = OwnedNative.CreateGeneratedFile(parent.Handle, parent.Leaf))
                using (var file = new FileStream(handle, FileAccess.ReadWrite))
                {
                    try
                    {
                        string path = Path.Combine(parent.Path, parent.Leaf); HostPaths.CheckHandle(handle, path, false); HostPaths.CheckPrivateFile(path);
                        string identity = HostPaths.FileIdentity(handle); WriteAndVerify(file, id, size); HostPaths.CheckHandle(handle, path, false);
                        if (HostPaths.FileIdentity(handle) != identity) throw new BrokerError("guest_fixture_owned_refused");
                        ledger.Items.Add(new OwnedFixture { Relative = relative, Identity = identity, Directory = false, GeneratedId = id, GeneratedBytes = size }); store.WriteOwned(root, ledger);
                    }
                    catch (Exception) { throw new BrokerError("guest_fixture_mutation_uncertain"); } // Private residue, never auto-delete or replay.
                }
            }
        }
    }
}
