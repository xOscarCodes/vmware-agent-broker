using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal enum OfficialTool { Vmrun, Vmcli }
    internal sealed class CliPlan
    {
        internal OfficialTool Tool;
        internal string[] Arguments;
        internal bool ReadOutput;
        internal static CliPlan Build(VmrunRequest request, Target target, string imagePath)
        {
            if (request.Entry.Backend != "official-vmrun-cli" && request.Entry.Backend != "official-vmcli-cli") throw new BrokerError("cli_plan_forbidden");
            var args = new List<string>();
            if (request.Entry.Name == "captureScreen")
            {
                if (target == null || imagePath == null || request.Arguments.Length != 0) throw new BrokerError("cli_plan_forbidden");
                return new CliPlan { Tool = OfficialTool.Vmcli, Arguments = new[] { target.Vmx, "MKS", "captureScreenshot", imagePath }, ReadOutput = false };
            }
            args.Add("-T"); args.Add("ws"); args.Add(request.Entry.Name);
            switch (request.Entry.Name)
            {
                case "listHostNetworks": if (target != null || request.Arguments.Length != 0) throw new BrokerError("cli_plan_forbidden"); break;
                case "listPortForwardings": if (target != null) throw new BrokerError("cli_plan_forbidden"); CliParsing.NetworkName(request.Arguments[0]); args.Add(request.Arguments[0]); break;
                case "setPortForwarding": case "deletePortForwarding":
                    if (target != null || request.Arguments[1] != "tcp") throw new BrokerError("cli_plan_forbidden");
                    CliParsing.NetworkName(request.Arguments[0]); OwnedForwarding.CanonicalPort(request.Arguments[2], true);
                    if (request.Entry.Name == "setPortForwarding") { ForwardPolicy.PrivateAddress(request.Arguments[3]); OwnedForwarding.CanonicalPort(request.Arguments[4], false); if (request.Arguments.Length != 6 || !Regex.IsMatch(request.Arguments[5], @"^broker-temporary-[A-F0-9]{32}$")) throw new BrokerError("cli_plan_forbidden"); }
                    args.AddRange(request.Arguments); break;
                case "getGuestIPAddress":
                    if (target == null) throw new BrokerError("cli_plan_forbidden"); args.Add(target.Vmx);
                    if (request.Arguments.Length != 0) { if (request.Arguments[0] != "-wait") throw new BrokerError("cli_plan_forbidden"); args.Add("-wait"); } break;
                case "upgradevm": if (target == null || request.Arguments.Length != 0) throw new BrokerError("cli_plan_forbidden"); args.Add(target.Vmx); break;
                case "connectNamedDevice": case "disconnectNamedDevice":
                    if (target == null) throw new BrokerError("cli_plan_forbidden"); DeviceBinding.Id(request.Arguments[0]); args.Add(target.Vmx); args.Add(request.Arguments[0]); break;
                case "removeSharedFolder":
                    if (target == null || request.Arguments.Length != 1) throw new BrokerError("cli_plan_forbidden"); VmrunRequest.Label(request.Arguments[0]); args.Add(target.Vmx); args.Add(request.Arguments[0]); break;
                case "disableSharedFolders":
                    if (target == null || request.Arguments.Length > 1 || (request.Arguments.Length == 1 && request.Arguments[0] != "runtime")) throw new BrokerError("cli_plan_forbidden"); args.Add(target.Vmx); if (request.Arguments.Length == 1) args.Add("runtime"); break;
                default: throw new BrokerError("cli_plan_forbidden");
            }
            return new CliPlan { Tool = OfficialTool.Vmrun, Arguments = args.ToArray(), ReadOutput = request.Entry.Name == "getGuestIPAddress" || request.Entry.Name == "listHostNetworks" || request.Entry.Name == "listPortForwardings" };
        }
    }
    internal sealed class CliReply : IDisposable
    {
        internal uint Exit;
        internal byte[] Output;
        public void Dispose() { if (Output != null) { Array.Clear(Output, 0, Output.Length); Output = null; } }
    }
    internal static class CliTools
    {
        internal const string VmrunPath = @"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe";
        internal const string VmcliPath = @"C:\Program Files (x86)\VMware\VMware Workstation\vmcli.exe";
        internal const string VmrunHash = "143CAEBFD00F46430C12BFFB743DDA1EF60A44082F6861CC89438B89BB1613C9";
        internal const string VmcliHash = "F8B6CB61CB237F107B66602A6F2B911A7845A33E91A60E7DDE7E6BA7755060F2";
        internal static CliReply Run(CliPlan plan, Func<bool> outputWithinLimit)
        {
            Diagnostics.At(Stage.CliVerify);
            string path = plan.Tool == OfficialTool.Vmrun ? VmrunPath : VmcliPath;
            string hash = plan.Tool == OfficialTool.Vmrun ? VmrunHash : VmcliHash;
            using (FileStream pin = Policy.OpenPinned(path))
            {
                using (var sha = SHA256.Create()) if (BitConverter.ToString(sha.ComputeHash(pin)).Replace("-", "") != hash) throw new BrokerError("unreviewed_cli_binary");
                VerifySignature(pin, path);
                // No credential flags accepted/generated, no shell, no arbitrary
                // executable or CWD. Only fixed official command plans reach here.
                Diagnostics.At(Stage.CliCall);
                return BoundedCli.Run(path, plan.Arguments, plan.ReadOutput, 30000, 32768, outputWithinLimit);
            }
        }
        private static void VerifySignature(FileStream file, string path)
        {
            var info = new Native.TrustFile { Size = (uint)Marshal.SizeOf(typeof(Native.TrustFile)), Path = path, File = file.SafeFileHandle.DangerousGetHandle() };
            IntPtr pointer = Marshal.AllocHGlobal((int)info.Size); Marshal.StructureToPtr(info, pointer, false);
            var trust = new Native.TrustData { Size = (uint)Marshal.SizeOf(typeof(Native.TrustData)), Ui = 2, UnionChoice = 1, File = pointer, StateAction = 1, Flags = 0x1010 };
            var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            try { if (Native.WinVerifyTrust(new IntPtr(-1), ref action, ref trust) != 0) throw new BrokerError("cli_signature_untrusted"); }
            finally { trust.StateAction = 2; Native.WinVerifyTrust(new IntPtr(-1), ref action, ref trust); Marshal.DestroyStructure(pointer, typeof(Native.TrustFile)); Marshal.FreeHGlobal(pointer); GC.KeepAlive(file); }
        }
    }
    internal static class CliParsing
    {
        internal static void NetworkName(string name) { if (!Regex.IsMatch(name ?? "", @"^vmnet(0|[1-9][0-9]{0,2})$", RegexOptions.CultureInvariant)) throw new BrokerError("invalid_request"); }
        internal static string Address(string value)
        {
            IPAddress address;
            if (value == null || value.Length > 45 || value.Contains("%") || value != value.Trim() || !IPAddress.TryParse(value, out address)) throw new BrokerError("cli_output_unrecognized");
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !Regex.IsMatch(value, @"^(\d{1,3}\.){3}\d{1,3}$")) throw new BrokerError("cli_output_unrecognized");
            return address.ToString();
        }
        internal static string Text(CliReply reply)
        {
            if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
            if (reply.Output == null || reply.Output.Length > 32768) throw new BrokerError("cli_output_limit");
            try { return new UTF8Encoding(false, true).GetString(reply.Output); } catch (ArgumentException) { throw new BrokerError("cli_output_unrecognized"); }
        }
        internal static OperationReport Parse(VmrunRequest request, CliReply reply)
        {
            string text = Text(reply);
            var report = OperationReport.New(request); report.Completion = "bounded_cli_observation";
            if (request.Entry.Name == "getGuestIPAddress") { report.Address = Address(text.Trim()); return report; }
            if (request.Entry.Name == "listHostNetworks" && Regex.IsMatch(text, @"(?m)^\s*(Total host networks:|INDEX\s+NAME)", RegexOptions.CultureInvariant)) return InstalledHostNetworks(text, report);
            var lines = text.Replace("\r\n", "\n").Split('\n');
            if (lines.Length > 258) throw new BrokerError("cli_output_limit");
            report.Inventory = new List<InventoryRow>(); int? declared = null;
            var identities = new HashSet<string>(); bool header = false;
            foreach (string raw in lines)
            {
                string line = raw.Trim(); if (line.Length == 0) continue;
                string totalPattern = request.Entry.Name == "listHostNetworks" ? @"^Total networks: ([0-9]{1,3})$" : @"^Total port forwardings: ([0-9]{1,3})$";
                Match total = Regex.Match(line, totalPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (total.Success) { if (declared.HasValue) throw new BrokerError("cli_output_unrecognized"); declared = Int32.Parse(total.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture); continue; }
                if (request.Entry.Name == "listHostNetworks")
                {
                    if (Regex.IsMatch(line, @"^Name\s+Type(?:\s+.*)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) { if (header) throw new BrokerError("cli_output_unrecognized"); header = true; continue; }
                    if (header && Regex.IsMatch(line, @"^-+(\s+-+)*$")) continue;
                    Match row = Regex.Match(line, @"^(vmnet(?:0|[1-9][0-9]{0,2}))\s+(bridged|nat|host-only|hostonly)(?:\s+[^\r\n]*)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    if (!row.Success) throw new BrokerError("cli_output_unrecognized");
                    string name = row.Groups[1].Value.ToLowerInvariant(); NetworkName(name);
                    if (!identities.Add(name)) throw new BrokerError("cli_output_unrecognized");
                    report.Inventory.Add(new InventoryRow { Name = name, Kind = row.Groups[2].Value.ToLowerInvariant().Replace("hostonly", "host-only") });
                }
                else
                {
                    if (Regex.IsMatch(line, @"^Protocol\s+Host\s*Port\s+Guest\s*IP\s+Guest\s*Port(?:\s+Description)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) { if (header) throw new BrokerError("cli_output_unrecognized"); header = true; continue; }
                    if (header && Regex.IsMatch(line, @"^-+(\s+-+)*$")) continue;
                    Match row = Regex.Match(line, @"^(tcp|udp)\s+([0-9]{1,5})\s+([0-9a-fA-F:.]+)\s+([0-9]{1,5})(?:\s+[^\r\n]*)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    if (!row.Success) throw new BrokerError("cli_output_unrecognized");
                    int host = Port(row.Groups[2].Value), guest = Port(row.Groups[4].Value); string protocol = row.Groups[1].Value.ToLowerInvariant();
                    if (!identities.Add(protocol + ":" + host)) throw new BrokerError("cli_output_unrecognized");
                    report.Inventory.Add(new InventoryRow { Name = request.Arguments[0], Kind = protocol, HostPort = host, GuestPort = guest, Address = Address(row.Groups[3].Value) });
                }
                if (report.Inventory.Count > 256) throw new BrokerError("cli_output_limit");
            }
            if ((!header && !declared.HasValue) || (report.Inventory.Count == 0 && declared != 0) || (declared.HasValue && declared != report.Inventory.Count)) throw new BrokerError("cli_output_unrecognized");
            report.Count = report.Inventory.Count; return report;
        }
        internal static int Port(string value) { int port; if (!Int32.TryParse(value, out port) || port < 1 || port > 65535) throw new BrokerError("cli_output_unrecognized"); return port; }
        private static uint LiteralIpv4(string text)
        {
            string[] parts = text.Split('.'); if (parts.Length != 4) throw new BrokerError("cli_output_unrecognized"); uint result = 0;
            foreach (string part in parts)
            {
                byte number;
                if (!Byte.TryParse(part, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out number) || number.ToString(System.Globalization.CultureInfo.InvariantCulture) != part) throw new BrokerError("cli_output_unrecognized");
                result = (result << 8) | number;
            }
            return result;
        }
        private static OperationReport InstalledHostNetworks(string text, OperationReport report)
        {
            // Actual installed six-column table reported by parent live test007.
            // Validate every input column; export ONLY public name/kind, no subnet,
            // mask, DHCP, index or arbitrary extra text. Old schema stays separate.
            var lines = new List<string>(); foreach (string line in text.Replace("\r\n", "\n").Split('\n')) if (line.Trim().Length != 0) lines.Add(line.Trim());
            if (lines.Count < 2 || lines.Count > 258) throw new BrokerError("cli_output_unrecognized");
            Match total = Regex.Match(lines[0], @"^Total host networks: (0|[1-9][0-9]{0,2})$", RegexOptions.CultureInvariant);
            if (!total.Success || !Regex.IsMatch(lines[1], @"^INDEX\s+NAME\s+TYPE\s+DHCP\s+SUBNET\s+MASK$", RegexOptions.CultureInvariant)) throw new BrokerError("cli_output_unrecognized");
            int declared = Int32.Parse(total.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            if (declared > 256 || lines.Count != declared + 2) throw new BrokerError("cli_output_unrecognized");
            report.Inventory = new List<InventoryRow>(); var names = new HashSet<string>(StringComparer.Ordinal); var indices = new HashSet<int>();
            for (int i = 0; i < declared; i++)
            {
                string[] fields = Regex.Split(lines[i + 2], @"\s+");
                // INDEX is an identifier, not a row ordinal. Parent observed1/8;
                // neither contiguity/order nor a relation to NAME is established.
                int index;
                if (fields.Length != 6 || !Int32.TryParse(fields[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out index) || index < 0 || fields[0] != index.ToString(System.Globalization.CultureInfo.InvariantCulture) || !indices.Add(index) || !names.Add(fields[1]) || (fields[3] != "true" && fields[3] != "false")) throw new BrokerError("cli_output_unrecognized");
                NetworkName(fields[1]);
                string kind = fields[2] == "hostOnly" ? "host-only" : fields[2];
                if (kind != "nat" && kind != "host-only" && kind != "bridged") throw new BrokerError("cli_output_unrecognized");
                uint subnet = LiteralIpv4(fields[4]), mask = LiteralIpv4(fields[5]), inverse = ~mask;
                if ((inverse & unchecked(inverse + 1)) != 0 || (subnet & inverse) != 0) throw new BrokerError("cli_output_unrecognized");
                report.Inventory.Add(new InventoryRow { Name = fields[1], Kind = kind });
            }
            report.Count = declared; return report;
        }
    }
}
