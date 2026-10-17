using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace GuestBroker
{
    // Protected, bounded, noncredential operation policy/journals. Separate from
    // VM registration and WinCred. Explicit root/publisher injection is test-only.
    internal sealed class HostMetadata
    {
        internal readonly string DirectoryPath, MachineBinding;
        private readonly Action<string, string, bool> publish;
        internal HostMetadata() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VmwareGuestBrokerHost"), Machine(), null) { }
        internal HostMetadata(string directory, string machine, Action<string, string, bool> publisher)
        {
            HostPaths.ApprovedRoot(directory); if (!Target.Hex(machine, 64)) throw new BrokerError("host_policy_invalid");
            DirectoryPath = directory; MachineBinding = machine;
            publish = publisher ?? delegate(string temp, string destination, bool exists) { if (exists) File.Replace(temp, destination, null); else File.Move(temp, destination); };
        }
        private static string Machine()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) return Hash(Environment.MachineName.ToUpperInvariant() + "\n" + identity.User.Value);
        }
        internal static string Hash(string text)
        { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", ""); }
        private string FilePath(string name)
        {
            if (!Regex.IsMatch(name ?? "", @"^[a-z]+(?:-[A-F0-9]{32})?\.json$")) throw new BrokerError("host_policy_invalid");
            return Path.Combine(DirectoryPath, name);
        }
        internal IDisposable Lock()
        {
            using (PinnedDirectory parent = PinnedDirectory.Open(Path.GetDirectoryName(DirectoryPath))) HostPaths.CreatePrivateDirectory(DirectoryPath);
            HostPaths.CheckPrivateDirectory(DirectoryPath);
            string path = Path.Combine(DirectoryPath, "writer.lock");
            if (File.Exists(path)) { Policy.NoReparse(path); HostPaths.CheckPrivateFile(path); }
            try { return new FileStream(path, FileMode.OpenOrCreate, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()); }
            catch (IOException) { throw new BrokerError("host_policy_busy"); }
        }
        internal T Read<T>(string name) where T : class
        {
            string path = FilePath(name);
            if (!Directory.Exists(DirectoryPath)) return null;
            using (PinnedDirectory directory = PinnedDirectory.Open(DirectoryPath, true))
            {
                HostPaths.CheckPrivateDirectory(DirectoryPath);
                FileStream file;
                try { file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete); } catch (FileNotFoundException) { return null; }
                using (file)
                {
                    HostPaths.CheckHandle(file.SafeFileHandle, path, false); HostPaths.CheckPrivateFile(path);
                    if (file.Length < 2 || file.Length > 65536) throw new BrokerError("host_policy_invalid");
                    var quotas = new XmlDictionaryReaderQuotas { MaxDepth = 16, MaxStringContentLength = 4096, MaxArrayLength = 512 };
                    try
                    {
                        using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(file, quotas))
                        {
                            T result = (T)new DataContractJsonSerializer(typeof(T), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 4096 }).ReadObject(reader);
                            if (reader.MoveToContent() != XmlNodeType.None) throw new BrokerError("host_policy_invalid"); return result;
                        }
                    }
                    catch (SerializationException) { throw new BrokerError("host_policy_invalid"); }
                }
            }
        }
        // Caller holds Lock across read/validate/change/publish/native transaction.
        internal void Write<T>(string name, T value)
        {
            string destination = FilePath(name);
            using (PinnedDirectory directory = PinnedDirectory.Open(DirectoryPath, true))
            {
                HostPaths.CheckPrivateDirectory(DirectoryPath);
                if (File.Exists(destination)) { Policy.NoReparse(destination); HostPaths.CheckPrivateFile(destination); }
                string temp = Path.Combine(DirectoryPath, "new-" + Guid.NewGuid().ToString("N"));
                try
                {
                    using (var file = new FileStream(temp, FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough, HostPaths.FileSecurity()))
                    {
                        new DataContractJsonSerializer(typeof(T), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 4096 }).WriteObject(file, value);
                        if (file.Length > 65536) throw new BrokerError("host_policy_invalid"); file.Flush(true);
                    }
                    publish(temp, destination, File.Exists(destination)); HostPaths.CheckPrivateFile(destination);
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
            }
        }
    }
}
