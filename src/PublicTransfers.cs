using System;
using System.IO;
using System.Runtime.Serialization;
using System.Text;

namespace GuestBroker
{
    [DataContract]
    internal sealed class PublicTransferRoot
    {
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal ExportRoot Host { get; set; }
        [DataMember(IsRequired = true)] internal string Guest { get; set; }
        internal void Validate()
        {
            if (!FixtureProtocol.Alias(Alias) || Host == null || String.IsNullOrEmpty(Host.Path) || Host.Path.Length > 70 || !Target.Hex(Host.Identity, 64)) throw new BrokerError("transfer_policy_invalid");
            HostPaths.ApprovedRoot(Host.Path); GuestPath(Guest);
        }
        internal static void GuestPath(string path)
        {
            // Lexical Windows path, not remote canonicalization/attestation.
            if (String.IsNullOrEmpty(path) || path.Length > 140 || path.Length < 4 || path[1] != ':' || path[2] != '\\' || path[0] < 'A' || path[0] > 'Z') throw new BrokerError("transfer_policy_invalid");
            foreach (string part in path.Substring(3).Split('\\'))
            {
                try { FixtureProtocol.Relative(part); } catch (BrokerError) { throw new BrokerError("transfer_policy_invalid"); }
                if (part.IndexOf('\\') >= 0) throw new BrokerError("transfer_policy_invalid");
            }
            string upper = path.ToUpperInvariant();
            if (upper == @"C:\WINDOWS" || upper.StartsWith(@"C:\WINDOWS\", StringComparison.Ordinal) || upper == @"C:\USERS" || upper.StartsWith(@"C:\PROGRAM", StringComparison.Ordinal)) throw new BrokerError("transfer_policy_invalid");
        }
    }
    internal interface IPublicTransferNative
    {
        bool Exists(string path, bool directory);
        void Info(string path, out long size, out int flags);
        void Copy(string source, string destination, bool toGuest);
    }
    internal static class PublicTransfers
    {
        internal static bool Command(string name) { return name == "CopyFileFromHostToGuest" || name == "CopyFileFromGuestToHost"; }
        internal static string Filename(string id)
        {
            if (!FixtureProtocol.Hex(id, 32)) throw new BrokerError("transfer_request_invalid");
            return "broker-public-" + id + ".bin";
        }
        internal static void FileInfo(long size, int flags, int expected)
        {
            if (flags != 0 || size != expected || size < 1 || size > GeneratedFixture.Maximum) throw new BrokerError("transfer_source_refused");
        }
        internal static void Execute(VmrunRequest request, PublicTransfer prepared, IPublicTransferNative native, OperationReport result)
        {
            bool dispatched = false;
            try
            {
                long size; int flags;
                if (!native.Exists(prepared.GuestRoot, true)) throw new BrokerError("transfer_source_refused");
                native.Info(prepared.GuestRoot, out size, out flags);
                if (flags != 1) throw new BrokerError("transfer_source_refused");
                if (request.Entry.Name == "CopyFileFromHostToGuest")
                {
                    if (native.Exists(prepared.GuestFile, false) || native.Exists(prepared.GuestFile, true)) throw new BrokerError("transfer_destination_exists");
                    prepared.VerifySource();
                    dispatched = true; Diagnostics.At(Stage.TransferCopy);
                    native.Copy(prepared.SourcePath, prepared.GuestFile, true);
                }
                native.Info(prepared.GuestFile, out size, out flags); FileInfo(size, flags, prepared.Size);
                // Real bytes cross the boundary here; verification NEVER regenerates
                // the received file or treats a guest-side generator as a copy.
                dispatched = true; Diagnostics.At(Stage.TransferCopy);
                native.Copy(prepared.GuestFile, prepared.ReceivePath, false);
                prepared.VerifyReceived();
                result.TransferId = prepared.Id; result.TransferBytes = prepared.Size; result.Fixture = prepared.Alias;
                result.Completion = request.Entry.Name == "CopyFileFromHostToGuest" ? "public_transfer_roundtrip_verified" : "public_transfer_received_verified";
            }
            catch (Exception)
            {
                // No cancellation acknowledgement is assumed. Leave unique private
                // residues in place; never retry, delete, rename or reuse a path.
                if (dispatched) throw new BrokerError("transfer_outcome_unknown");
                throw;
            }
        }
    }
    internal sealed class PublicTransfer : IDisposable
    {
        private PinnedDirectory root, bucket, fixture, receive;
        private FileStream source, receipt;
        internal string Id { get; private set; }
        internal int Size { get; private set; }
        internal string Alias { get; private set; }
        internal string GuestRoot { get; private set; }
        internal string GuestFile { get; private set; }
        internal string SourcePath { get; private set; }
        internal string ReceivePath { get; private set; }
        private PublicTransfer() { }
        internal static PublicTransfer Prepare(Target target, PublicTransferRoot policy, VmrunRequest request)
        {
            policy.Validate();
            if (!PublicTransfers.Command(request.Entry.Name) || request.Arguments[0] != policy.Alias) throw new BrokerError("transfer_not_approved");
            bool upload = request.Entry.Name == "CopyFileFromHostToGuest";
            var result = new PublicTransfer { Alias = policy.Alias, GuestRoot = policy.Guest, Id = upload ? request.GeneratedId : request.Arguments[1], Size = GeneratedFixture.Size(request.Arguments[upload ? 1 : 2]) };
            try
            {
                result.root = PinnedDirectory.Open(policy.Host.Path);
                if (result.root.Identity != policy.Host.Identity) throw new BrokerError("export_root_identity_changed");
                string bucketPath = Path.Combine(policy.Host.Path, "transfer-" + target.Binding);
                if (upload) HostPaths.CreatePrivateDirectory(bucketPath);
                result.bucket = PinnedDirectory.Open(bucketPath); HostPaths.CheckPrivateDirectory(bucketPath);
                string fixturePath = Path.Combine(bucketPath, result.Id);
                if (upload && !HostPaths.CreatePrivateDirectory(fixturePath)) throw new BrokerError("transfer_destination_exists");
                result.fixture = PinnedDirectory.Open(fixturePath); HostPaths.CheckPrivateDirectory(fixturePath);
                result.GuestFile = policy.Guest + "\\" + PublicTransfers.Filename(result.Id);
                result.SourcePath = Path.Combine(fixturePath, "source.bin");
                if (upload)
                {
                    using (var file = new FileStream(result.SourcePath, FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()))
                    { GeneratedFixture.WriteAndVerify(file, result.Id, result.Size); }
                }
                result.source = new FileStream(result.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                HostPaths.CheckHandle(result.source.SafeFileHandle, result.SourcePath, false); HostPaths.CheckPrivateFile(result.SourcePath);
                result.VerifySource();
                // A receipt proves broker-generated origin for this target/root,
                // not a previous successful transfer (unknown uploads may leave it).
                string receiptPath = Path.Combine(fixturePath, "origin.txt");
                string text = "BROKER-PUBLIC-TRANSFER-1\n" + target.Binding + "\n" + policy.Alias + "\n" + policy.Guest + "\n" + result.Id + "\n" + result.Size.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n" + HostPaths.FileIdentity(result.source.SafeFileHandle);
                byte[] expected = Encoding.UTF8.GetBytes(text);
                if (upload)
                {
                    using (var file = new FileStream(receiptPath, FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()))
                    { file.Write(expected, 0, expected.Length); file.Flush(true); }
                }
                result.receipt = new FileStream(receiptPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                HostPaths.CheckHandle(result.receipt.SafeFileHandle, receiptPath, false); HostPaths.CheckPrivateFile(receiptPath);
                if (result.receipt.Length != expected.Length) throw new BrokerError("transfer_source_refused");
                for (int i = 0; i < expected.Length; i++) if (result.receipt.ReadByte() != expected[i]) throw new BrokerError("transfer_source_refused");
                string receivePath = Path.Combine(fixturePath, "receive-" + Guid.NewGuid().ToString("N"));
                if (!HostPaths.CreatePrivateDirectory(receivePath)) throw new BrokerError("transfer_destination_exists");
                result.receive = PinnedDirectory.Open(receivePath); HostPaths.CheckPrivateDirectory(receivePath);
                result.ReceivePath = Path.Combine(receivePath, "received.bin");
                if (File.Exists(result.ReceivePath) || Directory.Exists(result.ReceivePath)) throw new BrokerError("transfer_destination_exists");
                return result;
            }
            catch { result.Dispose(); throw; }
        }
        internal void VerifySource() { GeneratedFixture.Verify(source, Id, Size); }
        internal void VerifyReceived()
        {
            using (var file = new FileStream(ReceivePath, FileMode.Open, System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.ChangePermissions | System.Security.AccessControl.FileSystemRights.TakeOwnership, FileShare.Read, 4096, FileOptions.None))
            {
                HostPaths.CheckHandle(file.SafeFileHandle, ReceivePath, false);
                // New VIX-created files initially inherit only the private receive
                // directory's owner ACE. Protect that same ACL on the open handle.
                file.SetAccessControl(HostPaths.FileSecurity()); HostPaths.CheckPrivateFile(ReceivePath);
                GeneratedFixture.Verify(file, Id, Size);
            }
        }
        public void Dispose()
        {
            if (receipt != null) { receipt.Dispose(); receipt = null; }
            if (source != null) { source.Dispose(); source = null; }
            if (receive != null) { receive.Dispose(); receive = null; }
            if (fixture != null) { fixture.Dispose(); fixture = null; }
            if (bucket != null) { bucket.Dispose(); bucket = null; }
            if (root != null) { root.Dispose(); root = null; }
            // Residues intentionally retained even on failure. No automatic cleanup.
        }
    }
}
