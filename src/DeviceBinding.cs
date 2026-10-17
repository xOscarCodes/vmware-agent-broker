using System;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class ExportRoot
    {
        [DataMember(IsRequired = true)] internal string Path { get; set; }
        [DataMember(IsRequired = true)] internal string Identity { get; set; }
        internal static ExportRoot Capture(string path)
        {
            HostPaths.ApprovedRoot(path);
            using (PinnedDirectory pin = PinnedDirectory.Open(path)) return new ExportRoot { Path = path, Identity = pin.Identity };
        }
    }
    [DataContract]
    internal sealed class ApprovedDevice
    {
        [DataMember(IsRequired = true)] internal string Id { get; set; }
        [DataMember(IsRequired = true)] internal string Fingerprint { get; set; }
        [DataMember(IsRequired = true)] internal string MediaPath { get; set; }
        [DataMember(IsRequired = true)] internal string MediaIdentity { get; set; }
    }
    internal static class DeviceBinding
    {
        internal static void Id(string value)
        {
            if (!Regex.IsMatch(value ?? "", @"^(sata|scsi|ide)[0-3]:([0-9]|1[0-5])$", RegexOptions.CultureInvariant)) throw new BrokerError("device_not_approved");
        }
        internal static string Field(Stream file, string key, bool optional = false)
        {
            // Whitelist is structural, not caller-controlled generic VMX access.
            // In particular no VNC/encryption/license/key or other value is read.
            if (!Regex.IsMatch(key, @"^((sata|scsi|ide|nvme)[0-3]:([0-9]|1[0-5])\.(deviceType|present|fileName)|nvram|extendedConfigFile|workingDir|checkpoint\.vmState)$", RegexOptions.CultureInvariant)) throw new BrokerError("device_not_approved");
            if (file.Length < 1 || file.Length > 4 * 1024 * 1024) throw new BrokerError("device_not_approved");
            file.Position = 0; string result = null; int c;
            while ((c = file.ReadByte()) >= 0)
            {
                while (c == ' ' || c == '\t' || c == '\r' || c == '\n') c = file.ReadByte();
                if (c < 0) break;
                bool matches = true;
                for (int i = 0; i < key.Length; i++)
                {
                    int left = c >= 'A' && c <= 'Z' ? c + 32 : c;
                    if (left != Char.ToLowerInvariant(key[i])) { matches = false; break; }
                    c = file.ReadByte();
                }
                if (matches) { while (c == ' ' || c == '\t') c = file.ReadByte(); matches = c == '='; }
                if (matches)
                {
                    var bytes = new MemoryStream();
                    while ((c = file.ReadByte()) >= 0 && c != '\r' && c != '\n')
                    { if (bytes.Length >= 1024) throw new BrokerError("device_not_approved"); bytes.WriteByte((byte)c); }
                    string value;
                    try { value = new UTF8Encoding(false, true).GetString(bytes.ToArray()).Trim(); } catch (ArgumentException) { throw new BrokerError("device_not_approved"); }
                    if (result != null || value.Length < 2 || value[0] != '"' || value[value.Length - 1] != '"') throw new BrokerError("device_not_approved");
                    result = value.Substring(1, value.Length - 2);
                    foreach (char letter in result) if (Char.IsControl(letter)) throw new BrokerError("device_not_approved");
                }
                else while (c >= 0 && c != '\n') c = file.ReadByte();
            }
            file.Position = 0;
            if (result == null && !optional) throw new BrokerError("device_not_approved"); return result;
        }
        private static string Descriptor(Stream file, string id, out string media)
        {
            Id(id);
            string type = Field(file, id + ".deviceType"), present = Field(file, id + ".present");
            media = Field(file, id + ".fileName");
            if (type != "cdrom-image" || !String.Equals(present, "TRUE", StringComparison.OrdinalIgnoreCase) || !media.EndsWith(".iso", StringComparison.OrdinalIgnoreCase)) throw new BrokerError("device_not_approved");
            if (media.Length > 240 || media.IndexOf(':', 2) >= 0 || media.IndexOfAny(new[] { '/', '"', '*', '?' }) >= 0 || !String.Equals(media, Path.GetFullPath(media), StringComparison.OrdinalIgnoreCase)) throw new BrokerError("device_not_approved");
            string directory = Path.GetDirectoryName(media);
            HostPaths.ApprovedRoot(directory);
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(id + "\n" + type + "\nTRUE\n" + media.ToUpperInvariant()))).Replace("-", "");
        }
        internal static ApprovedDevice Capture(Target target, string id)
        {
            using (FileStream vmx = VmIdentity.Open(target))
            {
                string media; string fingerprint = Descriptor(vmx, id, out media);
                using (FileStream pin = Policy.OpenPinned(media))
                {
                    HostPaths.CheckHandle(pin.SafeFileHandle, media, false);
                    return new ApprovedDevice { Id = id, Fingerprint = fingerprint, MediaPath = media, MediaIdentity = HostPaths.FileIdentity(pin.SafeFileHandle) };
                }
            }
        }
        internal static FileStream Validate(Target target, ApprovedDevice approved)
        {
            using (FileStream vmx = VmIdentity.Open(target))
            {
                string media;
                if (Descriptor(vmx, approved.Id, out media) != approved.Fingerprint || !String.Equals(media, approved.MediaPath, StringComparison.OrdinalIgnoreCase)) throw new BrokerError("device_identity_changed");
            }
            FileStream pin = Policy.OpenPinned(approved.MediaPath);
            try
            {
                HostPaths.CheckHandle(pin.SafeFileHandle, approved.MediaPath, false);
                if (HostPaths.FileIdentity(pin.SafeFileHandle) != approved.MediaIdentity) throw new BrokerError("device_identity_changed");
                return pin;
            }
            catch { pin.Dispose(); throw; }
        }
    }
}
