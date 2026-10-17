using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GuestBroker
{
    internal sealed class Request
    {
        internal string Operation;
        internal string TargetName;
        internal bool Stored, Persist;
        internal bool Json, Diagnostic;
        internal VmrunRequest Vmrun;
        internal string ExpectedBinding;
        internal string[] SetupArguments;
        internal static Request Parse(string[] args)
        {
            bool json = false, diagnostic = false;
            int literal = args.Length > 1 && args[0] == "vmrun" && args[1] == "runProgramInGuest" ? Array.IndexOf(args, "--") : -1;
            int length = literal >= 0 ? literal : args.Length;
            while (length > 0 && (args[length - 1] == "--json" || args[length - 1] == "--diagnostic"))
            {
                if (args[length - 1] == "--json") { if (json) throw new BrokerError("invalid_request"); json = true; }
                else { if (diagnostic) throw new BrokerError("invalid_request"); diagnostic = true; }
                length--;
            }
            int suffix = literal >= 0 ? args.Length - literal : 0;
            var input = new string[length + suffix]; Array.Copy(args, input, length);
            if (suffix != 0) Array.Copy(args, literal, input, length, suffix);
            Request request = ParseCommand(input);
            if (json && (request.Operation == "help" || request.Operation == "version")) throw new BrokerError("invalid_request");
            request.Json = json; request.Diagnostic = diagnostic;
            return request;
        }
        internal static bool RequestedJson(string[] args)
        {
            int end = args.Length;
            if (args.Length > 1 && args[0] == "vmrun" && args[1] == "runProgramInGuest") { int separator = Array.IndexOf(args, "--"); if (separator >= 0) end = separator; }
            return end > 0 && (args[end - 1] == "--json" || (end > 1 && args[end - 1] == "--diagnostic" && args[end - 2] == "--json"));
        }
        private static Request ParseCommand(string[] args)
        {
            if (args.Length > 0 && (args[0] == "setup-clones" || args[0] == "register-clone" || args[0] == "finalize-clone" || args[0] == "network-baseline" || args[0] == "setup-forwarding" || args[0] == "setup-photon"))
            {
                string setupOp = args[0];
                bool valid = setupOp == "setup-clones" ? args.Length == 5 && Target.ValidName(args[1]) && args[3] == "--expect-binding" && Target.Hex(args[4], 64) :
                    setupOp == "register-clone" ? args.Length == 4 && Target.ValidName(args[1]) && Target.Hex(args[2], 32) && Target.ValidName(args[3]) :
                    setupOp == "finalize-clone" ? args.Length == 3 && Target.ValidName(args[1]) && Target.Hex(args[2], 32) :
                    setupOp == "network-baseline" ? args.Length == 2 :
                    setupOp == "setup-forwarding" ? args.Length == 7 && Target.Hex(args[5], 64) && Target.Hex(args[6], 32) :
                    args.Length == 2 || args.Length == 6 && args[2] == "--existing-license-evidence" && Target.Hex(args[3], 32) && args[4] == "--license-sha256" && args[5] == PhotonDownload.LicenseHash;
                if (!valid) throw new BrokerError("invalid_request");
                if (setupOp == "setup-clones" || setupOp == "setup-photon") HostPaths.ApprovedRoot(args[setupOp == "setup-clones" ? 2 : 1]);
                if (setupOp == "network-baseline" || setupOp == "setup-forwarding") CliParsing.NetworkName(args[1]);
                var values = new string[args.Length - 1]; Array.Copy(args, 1, values, 0, values.Length); return new Request { Operation = setupOp, SetupArguments = values };
            }
            if (args.Length == 4 && args[0] == "rebind-knownvm" && Target.ValidName(args[1]) && args[2] == "--expect-binding" && Target.Hex(args[3], 64)) return new Request { Operation = "rebind-knownvm", TargetName = args[1], ExpectedBinding = args[3] };
            if (args.Length > 0 && args[0] == "vmrun")
            {
                var tokens = new string[args.Length - 1]; Array.Copy(args, 1, tokens, 0, tokens.Length);
                VmrunRequest operation = VmrunRequest.Parse(tokens);
                return new Request { Operation = "vmrun", TargetName = operation.TargetName, Vmrun = operation };
            }
            if (args.Length > 0 && args[0] == "catalog")
            {
                if (args.Length > 2) throw new BrokerError("invalid_request");
                if (args.Length == 2) Catalog.Find(args[1]);
                return new Request { Operation = "catalog", TargetName = args.Length == 2 ? args[1] : null };
            }
            if (args.Length == 2 && args[0] == "policy" && Target.ValidName(args[1])) return new Request { Operation = "policy", TargetName = args[1] };
            if (args.Length == 0 || (args.Length == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h"))) return new Request { Operation = "help" };
            if (args.Length == 1 && (args[0] == "version" || args[0] == "--version")) return new Request { Operation = "version" };
            if (args.Length == 1 && (args[0] == "probe" || args[0] == "list" || args[0] == "register")) return new Request { Operation = args[0] };
            if (args.Length < 2 || args.Length > 3 || !Target.ValidName(args[1])) throw new BrokerError("invalid_request");
            string op = args[0];
            if (op != "status" && op != "identity" && op != "timezone-melbourne" && op != "enroll" && op != "revoke" && op != "unregister")
                throw new BrokerError("invalid_request");
            var result = new Request { Operation = op, TargetName = args[1] };
            if (args.Length == 3)
            {
                if (args[2] == "--stored" && (op == "identity" || op == "timezone-melbourne")) result.Stored = true;
                else if (args[2] == "--persist" && op == "enroll") result.Persist = true;
                else throw new BrokerError("invalid_request");
            }
            return result;
        }
        internal string[] WorkerArguments()
        {
            if (SetupArguments != null) { var setup = new System.Collections.Generic.List<string> { Operation }; setup.AddRange(SetupArguments); return setup.ToArray(); }
            if (Vmrun != null)
            {
                var tokens = new System.Collections.Generic.List<string>(); tokens.Add("vmrun"); tokens.AddRange(Vmrun.Tokens()); return tokens.ToArray();
            }
            var args = new System.Collections.Generic.List<string>(); args.Add(Operation);
            if (TargetName != null) args.Add(TargetName);
            if (Operation == "rebind-knownvm") { args.Add("--expect-binding"); args.Add(ExpectedBinding); }
            if (Stored) args.Add("--stored");
            if (Persist) args.Add("--persist");
            return args.ToArray();
        }
    }

    internal static class Policy
    {
        internal const string Dll = @"C:\Program Files (x86)\VMware\VMware Workstation\vix.dll";
        internal const string DllSha256 = "F2C5A2686EF8004AF4FEA1477E6CD68801B504B2B0B5EE2D286A681FB4E5727C";
        internal const string TimezoneProgram = @"C:\Windows\System32\tzutil.exe";
        internal const string TimezoneArguments = "/s \"AUS Eastern Standard Time\"";

        // Reject redirection rather than accepting another VM that happens to have an alias.
        internal static void NoReparse(string path)
        {
            for (string current = path; !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new BrokerError("reparse_path_rejected");
            }
        }

        internal static FileStream OpenPinned(string path)
        {
            NoReparse(path);
            // Metadata only for VMX: never read its contents. Keep a handle during native use.
            var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                var resolved = new StringBuilder(1024);
                uint n = Native.GetFinalPathNameByHandleW(file.SafeFileHandle, resolved, (uint)resolved.Capacity, 0);
                if (n == 0 || n >= resolved.Capacity || !String.Equals(resolved.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
                    throw new BrokerError("canonical_path_mismatch");
                return file;
            }
            catch { file.Dispose(); throw; }
        }

        internal static void VerifyImage(byte[] image)
        {
            // Public PE format only; this is not decompilation or a behavioral claim.
            if (image.Length < 64 || image[0] != 'M' || image[1] != 'Z') throw new BrokerError("invalid_pe");
            int pe = BitConverter.ToInt32(image, 60);
            if (pe < 64 || pe > image.Length - 26 || BitConverter.ToUInt32(image, pe) != 0x4550)
                throw new BrokerError("invalid_pe");
            if (BitConverter.ToUInt16(image, pe + 4) != 0x14c || BitConverter.ToUInt16(image, pe + 24) != 0x10b)
                throw new BrokerError("unsupported_architecture");
        }

        internal static void VerifyHash(Stream file)
        {
            using (var sha = SHA256.Create())
            {
                string hash = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "");
                if (hash != DllSha256) throw new BrokerError("unreviewed_vix_binary");
            }
            file.Position = 0;
        }

        internal static string SafeHostname(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 63) throw new BrokerError("invalid_guest_identity");
            foreach (char c in value)
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
                    throw new BrokerError("invalid_guest_identity");
            return value;
        }
        internal static void RequireSameTargetPath(string actual, string expected)
        {
            if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) throw new BrokerError("native_target_mismatch");
        }
    }
}
