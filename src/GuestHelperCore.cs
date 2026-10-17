using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static class FixtureProtocol
    {
        internal const int Version = 4;
        internal const int Exists = 0, Missing = 1, Invalid = 20, RootChanged = 21, Redirected = 22, NotEnrolled = 23, ImageChanged = 24, IoFailure = 25, MutationUncertain = 26, MutationRefused = 27;
        internal static bool Hex(string value, int length) { return value != null && value.Length == length && Regex.IsMatch(value, "^[0-9A-F]+$", RegexOptions.CultureInvariant); }
        internal static bool Alias(string value) { return Regex.IsMatch(value ?? "", "^[A-Za-z][A-Za-z0-9_-]{0,31}$", RegexOptions.CultureInvariant); }
        internal static string Relative(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 128 || value.Contains("/") || value.Contains(":")) throw new BrokerError("guest_fixture_path_rejected");
            string[] components = value.Split('\\');
            if (components.Length > 8) throw new BrokerError("guest_fixture_path_rejected");
            foreach (string part in components)
            {
                if (!Regex.IsMatch(part, @"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$", RegexOptions.CultureInvariant) || part.EndsWith(".", StringComparison.Ordinal)) throw new BrokerError("guest_fixture_path_rejected");
                string stem = part.Split('.')[0].ToUpperInvariant(), lower = part.ToLowerInvariant();
                if (Regex.IsMatch(stem, @"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$") || lower.Contains("password") || lower.Contains("credential") || lower.Contains("privatekey") || lower.Contains("token") || lower.EndsWith(".pem") || lower.EndsWith(".key") || lower.EndsWith(".pfx") || lower.EndsWith(".p12") || lower.EndsWith(".kdbx")) throw new BrokerError("guest_fixture_path_rejected");
            }
            return value;
        }
        internal static string ImageHash(string file)
        {
            using (var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "");
        }
    }
    [DataContract]
    internal sealed class GuestRootRecord
    {
        [DataMember(IsRequired = true)] internal int Version = FixtureProtocol.Version;
        [DataMember(IsRequired = true)] internal string TargetBinding;
        [DataMember(IsRequired = true)] internal string Alias;
        [DataMember(IsRequired = true)] internal string EnrollmentId;
        [DataMember(IsRequired = true)] internal string RootPath;
        [DataMember(IsRequired = true)] internal string RootIdentity;
        [DataMember(IsRequired = true)] internal string ImageSha256;
        [DataMember(EmitDefaultValue = false)] internal bool OwnedMutations;
        [DataMember(EmitDefaultValue = false)] internal bool PublicListing;
        [DataMember(EmitDefaultValue = false)] internal bool OwnedRenames;
        [DataMember(EmitDefaultValue = false)] internal ApprovedListing ApprovedListing;
        [DataMember(EmitDefaultValue = false)] internal bool OwnedDeletes;
        [DataMember(EmitDefaultValue = false)] internal bool OwnedProcesses;
        [DataMember(EmitDefaultValue = false)] internal bool GeneratedFixtures;
        [DataMember(EmitDefaultValue = false)] internal bool OwnedSink;
        internal void Validate()
        {
            if (Version != FixtureProtocol.Version || !FixtureProtocol.Hex(TargetBinding, 64) || !FixtureProtocol.Alias(Alias) || !FixtureProtocol.Hex(EnrollmentId, 32) || !FixtureProtocol.Hex(RootIdentity, 64) || !FixtureProtocol.Hex(ImageSha256, 64)) throw new BrokerError("guest_fixture_policy_invalid");
            HostPaths.ApprovedRoot(RootPath);
            if (ApprovedListing != null) ApprovedListing.Validate();
        }
        internal static GuestRootRecord Capture(string target, string alias, string directory, string imageHash)
        {
            HostPaths.ApprovedRoot(directory);
            using (PinnedDirectory pin = PinnedDirectory.Open(directory, true))
            {
                var record = new GuestRootRecord { TargetBinding = target, Alias = alias, EnrollmentId = Guid.NewGuid().ToString("N").ToUpperInvariant(), RootPath = directory, RootIdentity = pin.Identity, ImageSha256 = imageHash };
                record.Validate(); return record;
            }
        }
    }
    internal sealed partial class GuestRootStore
    {
#if BROKER_TESTS
        // Deterministic held-reader publication seam; absent from broker/helper
        // production builds. Called only AFTER handle/path/ACL checks.
        internal Action<string, FileStream> ReadSnapshotOpened;
#endif
        private readonly string directory;
        internal GuestRootStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VmwareGuestBrokerHelper")) { }
        internal GuestRootStore(string root) { directory = Path.GetFullPath(root); HostPaths.ValidDirectory(directory); }
        private string FileName(string target, string alias)
        {
            if (!FixtureProtocol.Hex(target, 64) || !FixtureProtocol.Alias(alias)) throw new BrokerError("guest_fixture_policy_invalid");
            return Path.Combine(directory, target + "-" + alias + ".json");
        }
        internal void Save(GuestRootRecord record)
        {
            record.Validate();
            using (PinnedDirectory parent = PinnedDirectory.Open(Path.GetDirectoryName(directory)))
            {
                HostPaths.CreatePrivateDirectory(directory);
                using (PinnedDirectory pin = PinnedDirectory.Open(directory, true))
                {
                    HostPaths.CheckPrivateDirectory(directory);
                    string lockPath = Path.Combine(directory, "enrollment.lock");
                    if (File.Exists(lockPath)) HostPaths.CheckPrivateFile(lockPath);
                    using (var writer = new FileStream(lockPath, FileMode.OpenOrCreate, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()))
                    {
                    HostPaths.CheckHandle(writer.SafeFileHandle, lockPath, false);
                    string destination = FileName(record.TargetBinding, record.Alias);
                    if (File.Exists(destination)) { HostPaths.CheckPrivateFile(destination); using (var file = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete)) HostPaths.CheckHandle(file.SafeFileHandle, destination, false); }
                    string temp = Path.Combine(directory, "root.new." + Guid.NewGuid().ToString("N"));
                    try
                    {
                        using (var file = new FileStream(temp, FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, HostPaths.FileSecurity()))
                        { new DataContractJsonSerializer(typeof(GuestRootRecord)).WriteObject(file, record); file.Flush(true); }
                        if (File.Exists(destination)) File.Replace(temp, destination, null); else File.Move(temp, destination);
                        HostPaths.CheckPrivateFile(destination);
                    }
                    finally { if (File.Exists(temp)) File.Delete(temp); }
                    }
                }
            }
        }
        internal GuestRootRecord Read(string target, string alias)
        {
            string path = FileName(target, alias);
            // Protected STORE metadata snapshot, not a guest fixture directory:
            // an in-flight reader must not block Save's atomic child replacement.
            // Ancestors/store rename-delete protection remains; no in-place writes.
            using (PinnedDirectory pin = PinnedDirectory.Open(directory, true))
            {
                HostPaths.CheckPrivateDirectory(directory); HostPaths.CheckPrivateFile(path);
                // Protected METADATA only: allow atomic replacement/deletion,
                // never in-place writes. Fixture/export pins remain unchanged.
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                {
                    HostPaths.CheckHandle(file.SafeFileHandle, path, false);
#if BROKER_TESTS
                    if (ReadSnapshotOpened != null) ReadSnapshotOpened("enrollment", file);
#endif
                    if (file.Length < 2 || file.Length > 4096) throw new BrokerError("guest_fixture_policy_invalid");
                    var quotas = new XmlDictionaryReaderQuotas(); quotas.MaxDepth = 8; quotas.MaxStringContentLength = 1024;
                    using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                    {
                        var record = (GuestRootRecord)new DataContractJsonSerializer(typeof(GuestRootRecord)).ReadObject(reader);
                        if (reader.MoveToContent() != XmlNodeType.None) throw new BrokerError("guest_fixture_policy_invalid");
                        record.Validate(); if (record.TargetBinding != target || record.Alias != alias) throw new BrokerError("guest_fixture_policy_invalid"); return record;
                    }
                }
            }
        }
    }
    internal static class GuestProbe
    {
        internal static bool Exists(GuestRootRecord record, string relative, bool directory)
        {
            record.Validate(); relative = FixtureProtocol.Relative(relative);
            using (PinnedDirectory root = PinnedDirectory.Open(record.RootPath))
            {
                if (root.Identity != record.RootIdentity) throw new BrokerError("guest_fixture_root_changed");
                var handles = new List<SafeFileHandle>(); string current = record.RootPath;
                try
                {
                    string[] parts = relative.Split('\\');
                    for (int i = 0; i < parts.Length; i++)
                    {
                        current = Path.Combine(current, parts[i]);
                        var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                        SafeFileHandle handle = Native.CreateFileW(current, 0x81, 1, ref security, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
                        if (handle.IsInvalid)
                        {
                            int error = Marshal.GetLastWin32Error(); handle.Dispose();
                            if (error == 2 || error == 3) return false;
                            throw new BrokerError("guest_fixture_io_failed");
                        }
                        handles.Add(handle);
                        Native.FileInformation info;
                        if (!Native.GetFileInformationByHandle(handle, out info)) throw new BrokerError("guest_fixture_io_failed");
                        bool actualDirectory = (info.Attributes & 0x10) != 0;
                        HostPaths.CheckHandle(handle, current, actualDirectory);
                        if (i == parts.Length - 1) return actualDirectory == directory;
                        if (!actualDirectory) return false;
                    }
                    throw new BrokerError("guest_fixture_path_rejected");
                }
                finally { for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose(); }
            }
        }
        internal static int Request(GuestRootStore store, string selfHash, string[] args)
        {
            // operation, target hash, alias, enrollment generation, expected image
            // hash, relative path. All are non-secret scope metadata, never a password.
            if (args.Length < 6 || args.Length > 8 || (args[0] != "probe-file" && args[0] != "probe-directory" && args[0] != "list-counts" && args[0] != "list-approved" && args[0] != "rename-owned-file" && args[0] != "start-owned-process" && args[0] != "stop-owned-process" && args[0] != "type-owned-fixture" && args[0] != "create-generated-file" && !GuestOwned.Operation(args[0]) && !GuestDelete.Operation(args[0])) || (args[0] == "create-generated-file" ? args.Length != 8 : args[0] == "rename-owned-file" || args[0] == "list-approved" || args[0] == "type-owned-fixture" ? args.Length != 7 : args.Length != 6) || !FixtureProtocol.Hex(args[1], 64) || !FixtureProtocol.Alias(args[2]) || !FixtureProtocol.Hex(args[3], 32) || !FixtureProtocol.Hex(args[4], 64)) return FixtureProtocol.Invalid;
            if (selfHash != args[4]) return FixtureProtocol.ImageChanged;
            try
            {
                GuestRootRecord record = store.Read(args[1], args[2]);
                if (record.EnrollmentId != args[3] || record.ImageSha256 != selfHash) return FixtureProtocol.NotEnrolled;
                if (args[0] == "rename-owned-file") { GuestRename.Apply(store, record, args[5], args[6]); return 0; }
                if (GuestDelete.Operation(args[0])) { GuestDelete.Apply(store, record, args[5], args[0] == "delete-owned-tree"); return 0; }
                if (args[0] == "create-generated-file") { GeneratedFixture.Create(store, record, args[5], args[6], args[7]); return 0; }
                if (args[0] == "start-owned-process") { GuestProcessSupervisor.Start(store, record, args[5]); return 0; }
                if (args[0] == "stop-owned-process") { GuestProcessSupervisor.Stop(store, record, args[5]); return 0; }
                if (args[0] == "type-owned-fixture") { GuestProcessSupervisor.Type(store, record, args[5], args[6]); return 0; }
                if (args[0] == "list-counts" || args[0] == "list-approved")
                {
                    using (store.MutationLock())
                    {
                        record = store.Read(args[1], args[2]);
                        if (record.EnrollmentId != args[3] || record.ImageSha256 != selfHash) return FixtureProtocol.NotEnrolled;
                        return args[0] == "list-approved" ? GuestListing.ObserveApproved(record, args[5], args[6]) : GuestListing.Observe(record, args[5]).Encode();
                    }
                }
                if (GuestOwned.Operation(args[0])) { GuestOwned.Apply(store, record, args[0], args[5]); return FixtureProtocol.Exists; }
                return Exists(record, args[5], args[0] == "probe-directory") ? FixtureProtocol.Exists : FixtureProtocol.Missing;
            }
            catch (BrokerError error)
            {
                if (error.Code == "guest_fixture_root_changed") return FixtureProtocol.RootChanged;
                if (error.Code == "export_path_redirected") return FixtureProtocol.Redirected;
                if (error.Code == "guest_fixture_path_rejected") return FixtureProtocol.Invalid;
                if (error.Code == "guest_fixture_io_failed") return FixtureProtocol.IoFailure;
                if (error.Code == "guest_fixture_mutation_uncertain") return FixtureProtocol.MutationUncertain;
                if (GuestOwned.Operation(args[0]) || GuestDelete.Operation(args[0]) || args[0] == "rename-owned-file" || args[0] == "start-owned-process" || args[0] == "stop-owned-process" || args[0] == "type-owned-fixture" || args[0] == "create-generated-file") return FixtureProtocol.MutationRefused;
                return FixtureProtocol.NotEnrolled;
            }
            catch (Exception) { return FixtureProtocol.IoFailure; }
        }
    }
}
