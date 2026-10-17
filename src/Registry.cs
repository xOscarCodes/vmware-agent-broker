using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml;

namespace GuestBroker
{
    [DataContract]
    internal sealed class Target
    {
        [DataMember(IsRequired = true)] internal string Name;
        [DataMember(IsRequired = true)] internal string Vmx;
        [DataMember(IsRequired = true)] internal string Uuid;
        [DataMember(IsRequired = true)] internal string FileIdentity;
        [DataMember(IsRequired = true)] internal string Generation;
        // FileIdentity remains the immutable v2 binding seed, NOT a rotating key.
        [DataMember(EmitDefaultValue = false)] internal string IdentityMode { get; set; }
        [DataMember(EmitDefaultValue = false)] internal string ObservedFileIdentity { get; set; }
        [DataMember(EmitDefaultValue = false)] internal int IdentityRevision { get; set; }

        internal static bool ValidName(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 48 || !AsciiLetter(value[0])) return false;
            foreach (char c in value) if (!AsciiLetter(c) && !(c >= '0' && c <= '9') && c != '-' && c != '_') return false;
            return true;
        }
        private static bool AsciiLetter(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
        internal static bool Hex(string value, int length)
        {
            if (value == null || value.Length != length) return false;
            foreach (char c in value) if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F')) return false;
            return true;
        }
        internal static bool ValidPath(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > 240 || path.Length < 8 || path[1] != ':' || path[2] != '\\' || !AsciiLetter(path[0])) return false;
            if (!path.EndsWith(".vmx", StringComparison.OrdinalIgnoreCase) || path.IndexOfAny(new[] { '/', '"', '\r', '\n', '\0', '*', '?' }) >= 0) return false;
            if (path.IndexOf(':', 2) >= 0 || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return false;
            foreach (string part in path.Substring(3).Split('\\'))
                if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)) return false;
            return String.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase);
        }
        internal void Validate()
        {
            if (!ValidName(Name) || !ValidPath(Vmx) || !Hex(Uuid, 32) || !Hex(FileIdentity, 64) || !Hex(Generation, 32))
                throw new BrokerError("corrupt_registry");
            if (IdentityMode == null ? IdentityRevision != 0 || ObservedFileIdentity != null : IdentityMode != "path-uuid-v1" || IdentityRevision < 1 || !Hex(ObservedFileIdentity, 64)) throw new BrokerError("corrupt_registry");
        }
        internal string Binding
        {
            get
            {
                Validate();
                string input = "v2\n" + Name + "\n" + Vmx.ToUpperInvariant() + "\n" + Uuid + "\n" + FileIdentity + "\n" + Generation;
                using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(input))).Replace("-", "");
            }
        }
        internal string CredentialKey { get { return "VmwareGuestBroker/v2/" + Binding; } }
        internal bool SameRegistrationVersion(Target other)
        { return other != null && Binding == other.Binding && IdentityMode == other.IdentityMode && IdentityRevision == other.IdentityRevision && ObservedFileIdentity == other.ObservedFileIdentity; }
        internal Target Clone() { return (Target)MemberwiseClone(); }
    }

    [DataContract]
    internal sealed class RegistryDocument
    {
        [DataMember(IsRequired = true)] internal int Version = 2;
        [DataMember(IsRequired = true)] internal List<Target> Targets = new List<Target>();
        internal void Validate()
        {
            if (Version != 2 || Targets == null || Targets.Count > 64) throw new BrokerError("corrupt_registry");
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var uuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var generations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Target t in Targets)
            {
                if (t == null) throw new BrokerError("corrupt_registry");
                t.Validate();
                if (!names.Add(t.Name) || !paths.Add(t.Vmx) || !uuids.Add(t.Uuid) || !files.Add(t.FileIdentity) || !generations.Add(t.Generation))
                    throw new BrokerError("duplicate_registration");
            }
        }
        internal Target Resolve(string name)
        {
            Validate();
            foreach (Target t in Targets) if (String.Equals(t.Name, name, StringComparison.Ordinal)) return t.Clone();
            throw new BrokerError("unknown_target");
        }
    }

    internal sealed class RegistryStore
    {
        private readonly string directory, path;
        private readonly Action<string, string, bool> publish;
        private readonly SecurityIdentifier user;
        internal RegistryStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VmwareGuestBroker"), Publish) { }
        // Directory/publisher injection is internal and only used by synthetic tests.
        internal RegistryStore(string root, Action<string, string, bool> publisher)
        {
            directory = Path.GetFullPath(root);
            if (directory.StartsWith(@"\\", StringComparison.Ordinal) || new DriveInfo(Path.GetPathRoot(directory)).DriveType != DriveType.Fixed)
                throw new BrokerError("registry_requires_local_fixed_volume");
            path = Path.Combine(directory, "registry.json");
            publish = publisher;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) user = identity.User;
        }
        private static void Publish(string temp, string destination, bool exists)
        {
            if (exists) File.Replace(temp, destination, null);
            else File.Move(temp, destination);
        }
        private void CheckAcl(FileSystemSecurity security)
        {
            if (!user.Equals(security.GetOwner(typeof(SecurityIdentifier))) || !security.AreAccessRulesProtected)
                throw new BrokerError("registry_acl_rejected");
            bool ownerAllowed = false;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if (!user.Equals(rule.IdentityReference) || rule.IsInherited) throw new BrokerError("registry_acl_rejected");
                if ((rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl) ownerAllowed = true;
            }
            if (!ownerAllowed) throw new BrokerError("registry_acl_rejected");
        }
        private FileSecurity FileAcl()
        {
            var security = new FileSecurity();
            security.SetOwner(user);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
            return security;
        }
        private void CheckDirectory(bool create)
        {
            if (!Directory.Exists(directory))
            {
                if (!create) return;
                Policy.NoReparse(Path.GetDirectoryName(directory));
                var security = new DirectorySecurity();
                security.SetOwner(user);
                security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.CreateDirectory(directory, security);
            }
            Policy.NoReparse(directory);
            CheckAcl(Directory.GetAccessControl(directory));
        }
        internal RegistryDocument Read()
        {
            CheckDirectory(false);
            if (!Directory.Exists(directory)) return new RegistryDocument();
            FileAttributes attributes;
            try { attributes = File.GetAttributes(path); }
            catch (FileNotFoundException) { return new RegistryDocument(); }
            if ((attributes & FileAttributes.Directory) != 0) throw new BrokerError("corrupt_registry");
            Policy.NoReparse(path);
            CheckAcl(File.GetAccessControl(path));
            try
            {
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                {
                    if (file.Length < 2 || file.Length > 262144) throw new BrokerError("corrupt_registry");
                    var quotas = new XmlDictionaryReaderQuotas();
                    quotas.MaxDepth = 16; quotas.MaxStringContentLength = 4096;
                    quotas.MaxArrayLength = 128; quotas.MaxNameTableCharCount = 4096;
                    using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                    {
                        var serializer = new DataContractJsonSerializer(typeof(RegistryDocument), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 1024 });
                        var document = (RegistryDocument)serializer.ReadObject(reader);
                        if (reader.MoveToContent() != XmlNodeType.None) throw new BrokerError("corrupt_registry");
                        document.Validate();
                        return document;
                    }
                }
            }
            catch (BrokerError) { throw; }
            catch (Exception) { throw new BrokerError("corrupt_registry"); }
        }
        private void Update(Action<RegistryDocument> change)
        {
            CheckDirectory(true);
            string lockPath = Path.Combine(directory, "registry.lock");
            if (File.Exists(lockPath)) { Policy.NoReparse(lockPath); CheckAcl(File.GetAccessControl(lockPath)); }
            // One writer, no wait/retry or last-writer-wins overwrite. A stale lock
            // file is harmless; exclusivity belongs to its live handle.
            using (var mutex = LockWriter(lockPath))
            {
                RegistryDocument document = Read();
                change(document);
                document.Validate();
                string temp = Path.Combine(directory, "registry.new." + Guid.NewGuid().ToString("N"));
                try
                {
                    using (var file = new FileStream(temp, FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough, FileAcl()))
                    {
                        new DataContractJsonSerializer(typeof(RegistryDocument)).WriteObject(file, document);
                        if (file.Length > 262144) throw new BrokerError("registry_limit_exceeded");
                        file.Flush(true);
                    }
                    publish(temp, path, File.Exists(path));
                    CheckAcl(File.GetAccessControl(path));
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
            }
        }
        private FileStream LockWriter(string lockPath)
        {
            try { return new FileStream(lockPath, FileMode.OpenOrCreate, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, FileAcl()); }
            catch (IOException) { throw new BrokerError("registry_writer_unavailable"); }
        }
        internal void Add(Target target)
        {
            target.Validate();
            Update(delegate(RegistryDocument document) { document.Targets.Add(target.Clone()); });
        }
        internal void Remove(Target expected)
        {
            Update(delegate(RegistryDocument document)
            {
                Target current = document.Resolve(expected.Name);
                if (current.Binding != expected.Binding) throw new BrokerError("registration_changed");
                document.Targets.RemoveAll(delegate(Target t) { return t.Name == expected.Name; });
            });
        }
        internal Target RefreshKnownVm(string name, string expectedBinding)
        {
            if (!Target.ValidName(name) || !Target.Hex(expectedBinding, 64)) throw new BrokerError("invalid_request");
            if (name == "SAFE-DC") throw new BrokerError("protected_target_refused");
            Target refreshed = null; FileStream pin = null;
            try
            {
                Update(delegate(RegistryDocument document)
                {
                    Target current = document.Resolve(name);
                    if (current.Binding != expectedBinding || current.IdentityRevision == Int32.MaxValue) throw new BrokerError("registration_changed");
                    pin = VmIdentity.OpenLogical(current); string observed = VmIdentity.FileId(pin);
                    refreshed = current.Clone(); refreshed.IdentityMode = "path-uuid-v1"; refreshed.ObservedFileIdentity = observed;
                    refreshed.IdentityRevision = current.IdentityMode == "path-uuid-v1" && current.ObservedFileIdentity == observed ? current.IdentityRevision : current.IdentityRevision + 1;
                    if (refreshed.Binding != current.Binding || refreshed.CredentialKey != current.CredentialKey) throw new BrokerError("registration_changed");
                    int index = document.Targets.FindIndex(delegate(Target item) { return item.Name == name; }); document.Targets[index] = refreshed.Clone();
                });
                return refreshed;
            }
            finally { if (pin != null) pin.Dispose(); } // Current VMX/ancestor pins survive registry publication.
        }
        private static string PolicyName(Target target) { return "policy-" + target.Binding + ".json"; }
        internal CapabilityProfile ReadPolicy(Target target)
        {
            CheckDirectory(false);
            string filePath = Path.Combine(directory, PolicyName(target));
            if (!Directory.Exists(directory)) return CapabilityProfile.Default(target);
            FileAttributes attributes;
            try { attributes = File.GetAttributes(filePath); } catch (FileNotFoundException) { return CapabilityProfile.Default(target); }
            if ((attributes & FileAttributes.Directory) != 0) throw new BrokerError("capability_policy_invalid");
            Policy.NoReparse(filePath); CheckAcl(File.GetAccessControl(filePath));
            try
            {
                using (var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                {
                    if (file.Length > 32768) throw new BrokerError("capability_policy_invalid");
                    var quotas = new XmlDictionaryReaderQuotas(); quotas.MaxDepth = 16; quotas.MaxStringContentLength = 4096; quotas.MaxArrayLength = 128;
                    using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                    {
                        var profile = (CapabilityProfile)new DataContractJsonSerializer(typeof(CapabilityProfile), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 1024 }).ReadObject(reader);
                        if (reader.MoveToContent() != XmlNodeType.None) throw new BrokerError("capability_policy_invalid");
                        profile.Validate(target); return profile;
                    }
                }
            }
            catch (BrokerError) { throw; }
            catch (Exception) { throw new BrokerError("capability_policy_invalid"); }
        }
        internal void WritePolicy(Target target, CapabilityProfile profile)
        {
            profile.Validate(target); CheckDirectory(true);
            string lockPath = Path.Combine(directory, "registry.lock");
            if (File.Exists(lockPath)) { Policy.NoReparse(lockPath); CheckAcl(File.GetAccessControl(lockPath)); }
            using (var held = LockWriter(lockPath))
            {
                if (Read().Resolve(target.Name).Binding != target.Binding) throw new BrokerError("registration_changed");
                string destination = Path.Combine(directory, PolicyName(target));
                if (File.Exists(destination)) { Policy.NoReparse(destination); CheckAcl(File.GetAccessControl(destination)); }
                string temp = Path.Combine(directory, "policy.new." + Guid.NewGuid().ToString("N"));
                try
                {
                    using (var file = new FileStream(temp, FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough, FileAcl()))
                    {
                        // New optional manifests must not let the writer publish a
                        // policy the existing bounded reader cannot deserialize.
                        try { new DataContractJsonSerializer(typeof(CapabilityProfile), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 1024 }).WriteObject(file, profile); }
                        catch (SerializationException) { throw new BrokerError("capability_policy_invalid"); }
                        if (file.Length > 32768) throw new BrokerError("capability_policy_invalid"); file.Flush(true);
                    }
                    publish(temp, destination, File.Exists(destination));
                    CheckAcl(File.GetAccessControl(destination));
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
            }
        }
    }
}
