using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class ApprovedScript
    {
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal ExportRoot Root { get; set; }
        [DataMember(IsRequired = true)] internal string FileName { get; set; }
        [DataMember(IsRequired = true)] internal string FileIdentity { get; set; }
        [DataMember(IsRequired = true)] internal string Sha256 { get; set; }
        [DataMember(IsRequired = true)] internal string Interpreter { get; set; }
        internal void Validate()
        {
            if (!Target.ValidName(Alias) || Root == null || !Target.Hex(Root.Identity, 64) || !Target.Hex(FileIdentity, 64) || !Target.Hex(Sha256, 64) ||
                !Regex.IsMatch(FileName ?? "", @"^[A-Za-z0-9][A-Za-z0-9_-]{0,59}\.ps1$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
                (Interpreter != @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" && Interpreter != @"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"))
                throw new BrokerError("script_policy_invalid");
            HostPaths.ApprovedRoot(Root.Path);
        }
        internal static ApprovedScript Enroll(string alias, string filePath, string interpreter)
        {
            // Called only by explicit user policy UI (tests use owned fixtures).
            // No code/text/path is accepted from the agent CLI.
            var script = new ApprovedScript { Alias = alias, Root = ExportRoot.Capture(Path.GetDirectoryName(filePath)), FileName = Path.GetFileName(filePath), Interpreter = interpreter, FileIdentity = new string('0', 64), Sha256 = new string('0', 64) };
            script.Validate();
            using (PinnedScript pin = PinnedScript.Open(script, true))
            { script.FileIdentity = pin.FileIdentity; script.Sha256 = pin.Sha256; }
            return script;
        }
    }
    internal sealed class PinnedScript : IDisposable
    {
        internal const int MaximumBytes = 16384;
        internal const string Carrier = "native_runprogram_powershell_encoded";
        internal const string ArgumentPrefix = "-NoLogo -NoProfile -NonInteractive -EncodedCommand ";
        private PinnedDirectory root;
        private FileStream file;
        private SecretBuffer code, arguments;
        internal string FileIdentity { get; private set; }
        internal string Sha256 { get; private set; }
        internal IntPtr Code { get { return code.Pointer; } }
        internal IntPtr Arguments { get { return arguments.Pointer; } }
        private PinnedScript() { }
        internal static PinnedScript Open(ApprovedScript approved, bool enrollment)
        {
            approved.Validate();
            var result = new PinnedScript(); byte[] bytes = null;
            try
            {
                result.root = PinnedDirectory.Open(approved.Root.Path);
                if (result.root.Identity != approved.Root.Identity) throw new BrokerError("script_identity_changed");
                string path = Path.Combine(approved.Root.Path, approved.FileName);
                result.file = Policy.OpenPinned(path); HostPaths.CheckHandle(result.file.SafeFileHandle, path, false);
                result.FileIdentity = HostPaths.FileIdentity(result.file.SafeFileHandle);
                if (result.file.Length < 1 || result.file.Length > MaximumBytes) throw new BrokerError("script_size_rejected");
                bytes = new byte[(int)result.file.Length]; int offset = 0;
                while (offset < bytes.Length) { int n = result.file.Read(bytes, offset, bytes.Length - offset); if (n == 0) throw new BrokerError("script_identity_changed"); offset += n; }
                using (var sha = SHA256.Create()) result.Sha256 = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
                if (!enrollment && (result.FileIdentity != approved.FileIdentity || result.Sha256 != approved.Sha256)) throw new BrokerError("script_identity_changed");
                int start = bytes.Length >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191 ? 3 : 0;
                if (start == bytes.Length) throw new BrokerError("script_size_rejected");
                try { new UTF8Encoding(false, true).GetCharCount(bytes, start, bytes.Length - start); } catch (ArgumentException) { throw new BrokerError("script_encoding_rejected"); }
                for (int i = start; i < bytes.Length; i++) if (bytes[i] < 32 && bytes[i] != 9 && bytes[i] != 10 && bytes[i] != 13) throw new BrokerError("script_encoding_rejected");
                result.code = new SecretBuffer(bytes.Length - start + 1);
                Marshal.Copy(bytes, start, result.code.Pointer, bytes.Length - start);
                result.arguments = BuildArguments(approved.Interpreter, bytes, start, bytes.Length - start);
                return result;
            }
            catch { result.Dispose(); throw; }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
        }
        internal static SecretBuffer BuildArguments(string interpreter, byte[] utf8, int start, int count)
        {
            byte[] unicode = null, ascii = null;
            try
            {
                // Microsoft Windows PowerShell5.1 EncodedCommand is UTF-16LE,
                // NOT UTF-8 Base64. No wrapper, appended exit0, temp file, policy
                // override or caller argument is injected into the pinned code.
                string text;
                try { text = new UTF8Encoding(false, true).GetString(utf8, start, count); }
                catch (ArgumentException) { throw new BrokerError("script_encoding_rejected"); }
                unicode = new UnicodeEncoding(false, false, true).GetBytes(text);
                string command = ArgumentPrefix + Convert.ToBase64String(unicode);
                if (WindowsArguments.Quote(interpreter).Length + 1 + command.Length + 1 > 32767) throw new BrokerError("script_size_rejected");
                ascii = Encoding.ASCII.GetBytes(command); var buffer = new SecretBuffer(ascii.Length + 1);
                try { Marshal.Copy(ascii, 0, buffer.Pointer, ascii.Length); return buffer; }
                catch { buffer.Dispose(); throw; }
            }
            finally { if (unicode != null) Array.Clear(unicode, 0, unicode.Length); if (ascii != null) Array.Clear(ascii, 0, ascii.Length); }
        }
        public void Dispose()
        {
            if (arguments != null) { arguments.Dispose(); arguments = null; }
            if (code != null) { code.Dispose(); code = null; }
            if (file != null) { file.Dispose(); file = null; }
            if (root != null) { root.Dispose(); root = null; }
        }
    }
}
