using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class ForwardRow
    {
        [DataMember(IsRequired = true)] internal string Protocol, Address, Description;
        [DataMember(IsRequired = true)] internal int HostPort, GuestPort;
        internal string Key { get { return Protocol + ":" + HostPort; } }
        internal string Canonical { get { return Key + " " + Address + " " + GuestPort + " " + Description.Length + ":" + Description; } }
        internal void Validate()
        {
            if ((Protocol != "tcp" && Protocol != "udp") || HostPort < 1 || HostPort > 65535 || GuestPort < 1 || GuestPort > 65535 || Address == null || CliParsing.Address(Address) != Address || Description == null || Description.Length > 512) throw new BrokerError("forward_snapshot_invalid");
            foreach (char c in Description) if (Char.IsControl(c)) throw new BrokerError("forward_snapshot_invalid");
        }
    }
    [DataContract]
    internal sealed class ForwardSnapshot
    {
        [DataMember(IsRequired = true)] internal string Network;
        [DataMember(IsRequired = true)] internal List<ForwardRow> Rows = new List<ForwardRow>();
        internal void Validate()
        {
            CliParsing.NetworkName(Network); if (Rows == null || Rows.Count > 256) throw new BrokerError("forward_snapshot_invalid"); var keys = new HashSet<string>();
            foreach (ForwardRow row in Rows) { if (row == null) throw new BrokerError("forward_snapshot_invalid"); row.Validate(); if (!keys.Add(row.Key)) throw new BrokerError("forward_snapshot_invalid"); }
        }
        internal string Digest()
        {
            Validate(); var lines = new List<string>(); foreach (ForwardRow row in Rows) lines.Add(row.Canonical); lines.Sort(StringComparer.Ordinal);
            return HostMetadata.Hash(Network + "\n" + String.Join("\n", lines.ToArray()));
        }
        internal ForwardSnapshot Plus(ForwardRow row)
        { var result = new ForwardSnapshot { Network = Network, Rows = new List<ForwardRow>(Rows) }; result.Rows.Add(row); result.Validate(); return result; }
        internal static ForwardSnapshot Parse(string network, string text)
        {
            var result = new ForwardSnapshot { Network = network }; bool header = false; int? count = null;
            foreach (string raw in text.Replace("\r\n", "\n").Split('\n'))
            {
                string line = raw.Trim(); if (line.Length == 0) continue;
                Match total = Regex.Match(line, @"^Total port forwardings: (0|[1-9][0-9]{0,2})$", RegexOptions.IgnoreCase);
                if (total.Success) { if (count.HasValue) throw new BrokerError("forward_snapshot_invalid"); count = Int32.Parse(total.Groups[1].Value, CultureInfo.InvariantCulture); continue; }
                if (Regex.IsMatch(line, @"^Protocol\s+Host\s*Port\s+Guest\s*IP\s+Guest\s*Port(?:\s+Description)?$", RegexOptions.IgnoreCase)) { if (header) throw new BrokerError("forward_snapshot_invalid"); header = true; continue; }
                if (header && Regex.IsMatch(line, @"^-+(\s+-+)*$")) continue;
                Match entry = Regex.Match(line, @"^(tcp|udp)\s+([0-9]{1,5})\s+([0-9A-Fa-f:.]+)\s+([0-9]{1,5})(?:\s+(.*))?$", RegexOptions.IgnoreCase);
                if (!entry.Success || result.Rows.Count >= 256) throw new BrokerError("forward_snapshot_invalid");
                result.Rows.Add(new ForwardRow { Protocol = entry.Groups[1].Value.ToLowerInvariant(), HostPort = CliParsing.Port(entry.Groups[2].Value), GuestPort = CliParsing.Port(entry.Groups[4].Value), Address = CliParsing.Address(entry.Groups[3].Value), Description = entry.Groups[5].Success ? entry.Groups[5].Value : "" });
            }
            if ((!header && !count.HasValue) || result.Rows.Count == 0 && count != 0 || count.HasValue && count != result.Rows.Count) throw new BrokerError("forward_snapshot_invalid");
            result.Validate(); return result;
        }
    }
    [DataContract]
    internal sealed class ForwardPolicy
    {
        // Compatible historical wire name: an external owner-scope evidence
        // reference, NOT a measured-isolation assertion. It may record explicit
        // acceptance of all-host-interface exposure for one bounded test instead.
        // No evidence ID is synthesized here; exact tuple/ownership/snapshot checks
        // remain mandatory. Duration/removal is parent-supervised, not an auto TTL.
        [DataMember(IsRequired = true)] internal string Machine, Id, IsolationEvidence, State;
        [DataMember(IsRequired = true)] internal long ExpiresUtcTicks;
        [DataMember(IsRequired = true)] internal ForwardSnapshot Original;
        [DataMember(IsRequired = true)] internal ForwardRow Owned;
        internal void Validate(string machine)
        {
            if (Machine != machine || !Target.Hex(Id, 32) || !Target.Hex(IsolationEvidence, 32) || Array.IndexOf(new[] { "configured", "prepared", "active", "removing", "removed" }, State) < 0 || Original == null || Owned == null || ExpiresUtcTicks < DateTime.MinValue.Ticks || ExpiresUtcTicks > DateTime.MaxValue.Ticks) throw new BrokerError("forward_policy_required");
            Original.Validate(); Owned.Validate(); PrivateAddress(Owned.Address);
            if (Owned.Protocol != "tcp" || Owned.HostPort < 49152 || Owned.Description != "broker-temporary-" + Id || Original.Rows.Exists(delegate (ForwardRow row) { return row.HostPort == Owned.HostPort; })) throw new BrokerError("forward_policy_required");
        }
        internal static string PrivateAddress(string value)
        {
            IPAddress address; if (!IPAddress.TryParse(value, out address) || address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != value) throw new BrokerError("forward_policy_required");
            byte[] bytes = address.GetAddressBytes();
            if (!(bytes[0] == 10 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31 || bytes[0] == 192 && bytes[1] == 168)) throw new BrokerError("forward_policy_required"); return value;
        }
    }
    internal interface IForwardNative
    {
        bool IsNat(string network);
        bool PortFree(int port);
        ForwardSnapshot Read(string network);
        void Add(string network, ForwardRow row);
        void Remove(string network, ForwardRow row);
    }
    internal sealed class ForwardNative : IForwardNative
    {
        private static VmrunRequest Request(params string[] tokens) { return VmrunRequest.Parse(tokens); }
        public bool IsNat(string network)
        {
            VmrunRequest request = Request("listHostNetworks");
            using (CliReply reply = CliTools.Run(CliPlan.Build(request, null, null), null))
            { OperationReport report = CliParsing.Parse(request, reply); return report.Inventory.Exists(delegate (InventoryRow row) { return row.Name == network && row.Kind == "nat"; }); }
        }
        public bool PortFree(int port)
        {
            foreach (IPEndPoint endpoint in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()) if (endpoint.Port == port) return false;
            try { using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) { socket.ExclusiveAddressUse = true; socket.Bind(new IPEndPoint(IPAddress.Any, port)); } return true; }
            catch (SocketException) { return false; }
        }
        public ForwardSnapshot Read(string network)
        {
            using (CliReply reply = CliTools.Run(CliPlan.Build(Request("listPortForwardings", network), null, null), null)) return ForwardSnapshot.Parse(network, CliParsing.Text(reply));
        }
        public void Add(string network, ForwardRow row)
        {
            VmrunRequest request = Request("setPortForwarding", network, "tcp", row.HostPort.ToString(CultureInfo.InvariantCulture), row.Address, row.GuestPort.ToString(CultureInfo.InvariantCulture), row.Description);
            using (CliReply reply = CliTools.Run(CliPlan.Build(request, null, null), null)) if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
        }
        public void Remove(string network, ForwardRow row)
        {
            using (CliReply reply = CliTools.Run(CliPlan.Build(Request("deletePortForwarding", network, "tcp", row.HostPort.ToString(CultureInfo.InvariantCulture)), null, null), null)) if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
        }
    }
    internal static class OwnedForwarding
    {
        internal static bool Command(string name) { return name == "setPortForwarding" || name == "deletePortForwarding"; }
        internal static int CanonicalPort(string text, bool high)
        { int port = CliParsing.Port(text); if (port.ToString(CultureInfo.InvariantCulture) != text || high && port < 49152) throw new BrokerError("forward_policy_required"); return port; }
        internal static ForwardPolicy Configure(HostMetadata store, IForwardNative native, string network, int host, string address, int guest, string expected, string scopeEvidence, DateTime now)
        {
            if (!Target.Hex(expected, 64) || !Target.Hex(scopeEvidence, 32) || host < 49152 || host > 65535 || guest < 1 || guest > 65535) throw new BrokerError("forward_policy_required"); ForwardPolicy.PrivateAddress(address);
            using (store.Lock())
            {
                ForwardPolicy old = store.Read<ForwardPolicy>("forward.json");
                if (old != null) { old.Validate(store.MachineBinding); if (old.State != "removed" && old.State != "configured") throw new BrokerError("forward_ownership_conflict"); }
                if (!native.IsNat(network) || !native.PortFree(host)) throw new BrokerError("forward_scope_refused");
                ForwardSnapshot original = native.Read(network);
                if (original.Network != network || original.Digest() != expected || original.Rows.Exists(delegate (ForwardRow row) { return row.HostPort == host; })) throw new BrokerError("forward_snapshot_changed");
                string id = Guid.NewGuid().ToString("N").ToUpperInvariant();
                var policy = new ForwardPolicy { Machine = store.MachineBinding, Id = id, Original = original, Owned = new ForwardRow { Protocol = "tcp", HostPort = host, Address = address, GuestPort = guest, Description = "broker-temporary-" + id }, State = "configured", IsolationEvidence = scopeEvidence, ExpiresUtcTicks = now.AddMinutes(30).Ticks };
                policy.Validate(store.MachineBinding); store.Write("forward.json", policy); return policy;
            }
        }
        internal static void Execute(VmrunRequest request, HostMetadata store, IForwardNative native, DateTime now, OperationReport result)
        {
            using (store.Lock())
            {
                ForwardPolicy policy = store.Read<ForwardPolicy>("forward.json"); if (policy == null) throw new BrokerError("forward_policy_required"); policy.Validate(store.MachineBinding);
                if (request.Arguments[0] != policy.Original.Network || request.Arguments[1] != "tcp" || CanonicalPort(request.Arguments[2], true) != policy.Owned.HostPort || !native.IsNat(policy.Original.Network)) throw new BrokerError("forward_scope_refused");
                bool add = request.Entry.Name == "setPortForwarding";
                if (add && (request.Arguments[3] != policy.Owned.Address || CanonicalPort(request.Arguments[4], false) != policy.Owned.GuestPort || request.Arguments.Length == 6 && request.Arguments[5] != policy.Owned.Description)) throw new BrokerError("forward_scope_refused");
                ForwardSnapshot current = native.Read(policy.Original.Network); string before = policy.Original.Digest(), after = policy.Original.Plus(policy.Owned).Digest();
                if (add)
                {
                    if (policy.State != "configured" || now.Ticks > policy.ExpiresUtcTicks || current.Digest() != before || !native.PortFree(policy.Owned.HostPort)) throw new BrokerError("forward_snapshot_changed");
                    policy.State = "prepared"; store.Write("forward.json", policy);
                }
                else
                {
                    if (policy.State != "prepared" && policy.State != "active" && policy.State != "removing") throw new BrokerError("forward_ownership_conflict");
                    if (current.Digest() == before) { policy.State = "removed"; store.Write("forward.json", policy); result.MappingId = policy.Id; result.Completion = "owned_forward_restored"; return; }
                    if (current.Digest() != after) throw new BrokerError("forward_snapshot_changed");
                    policy.State = "removing"; store.Write("forward.json", policy);
                }
                try
                {
                    if (add) native.Add(policy.Original.Network, policy.Owned); else native.Remove(policy.Original.Network, policy.Owned);
                    if (native.Read(policy.Original.Network).Digest() != (add ? after : before)) throw new BrokerError("forward_snapshot_changed");
                    policy.State = add ? "active" : "removed"; store.Write("forward.json", policy);
                    result.MappingId = policy.Id; result.Completion = add ? "owned_forward_added" : "owned_forward_restored";
                }
                catch (Exception) { Diagnostics.Fault(); throw new BrokerError("forward_outcome_unknown"); }
            }
        }
    }
}
