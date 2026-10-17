using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class CatalogEntry
    {
        [DataMember(Name = "name", IsRequired = true)] internal string Name { get; set; }
        [DataMember(Name = "syntax", IsRequired = true)] internal string Syntax { get; set; }
        [DataMember(Name = "accepted", IsRequired = true)] internal string Accepted { get; set; }
        [DataMember(Name = "guest", IsRequired = true)] internal string Guest { get; set; }
        [DataMember(Name = "risk", IsRequired = true)] internal string Risk { get; set; }
        [DataMember(Name = "backend", IsRequired = true)] internal string Backend { get; set; }
        [DataMember(Name = "state", IsRequired = true)] internal string State { get; set; }
        [DataMember(Name = "exports", IsRequired = true)] internal string Exports { get; set; }
        [DataMember(Name = "gate", IsRequired = true)] internal string Gate { get; set; }
        [DataMember(Name = "synthetic", IsRequired = true)] internal string Synthetic { get; set; }
        [DataMember(Name = "live", IsRequired = true)] internal string Live { get; set; }
        internal bool Enabled { get { return (Backend == "native-vix" || Backend == "native-vix-helper" || Backend == "official-vmrun-cli" || Backend == "official-vmcli-cli" || Backend == "official-https") && (State == "implemented" || State == "partial"); } }
        internal bool TargetScoped { get { return Name != "list" && Name != "listHostNetworks" && Name != "listPortForwardings" && Name != "setPortForwarding" && Name != "deletePortForwarding" && Name != "downloadPhotonVM"; } }
        internal bool NeedsCredential { get { return Guest == "required"; } }
        internal bool SensitiveRisk { get { return Risk != "metadata"; } }
        internal bool NeedsConsent { get { return OperationAuthorization.RequiresPrompt; } }
        internal bool NeedsDisposable { get { return Risk == "destructive" || Risk == "vm-mutation" || Risk == "privileged-execution" || Risk == "device-optical" || Risk == "sensitive-export" || Risk == "guest-fixture-probe" || Risk == "guest-fixture-mutation" || Risk == "file-transfer" || Risk == "host-file-sharing"; } }
    }
    [DataContract]
    internal sealed class CatalogIndexEntry
    {
        [DataMember(Name = "name", IsRequired = true)] internal string Name;
        [DataMember(Name = "state", IsRequired = true)] internal string State;
        [DataMember(Name = "backend", IsRequired = true)] internal string Backend;
        [DataMember(Name = "guest", IsRequired = true)] internal string Guest;
        internal static CatalogIndexEntry From(CatalogEntry entry) { return new CatalogIndexEntry { Name = entry.Name, State = entry.State, Backend = entry.Backend, Guest = entry.Guest }; }
    }
    [DataContract]
    internal sealed class CatalogDocument
    {
        [DataMember(Name = "schema", IsRequired = true)] internal int Schema { get; set; }
        [DataMember(Name = "installedVersion", IsRequired = true)] internal string Version { get; set; }
        [DataMember(Name = "installedSha256", IsRequired = true)] internal string Hash { get; set; }
        [DataMember(Name = "evidence", IsRequired = true)] internal string Evidence { get; set; }
        [DataMember(Name = "operationApproval", IsRequired = true)] internal string OperationApproval { get; set; }
        [DataMember(Name = "commands", IsRequired = true)] internal List<CatalogEntry> Commands { get; set; }
    }
    internal static class Catalog
    {
        private static readonly CatalogDocument document = Load();
        internal static IList<CatalogEntry> Entries { get { return document.Commands.AsReadOnly(); } }
        private static CatalogDocument Load()
        {
            using (Stream input = typeof(Catalog).Assembly.GetManifestResourceStream("GuestBroker.Catalog"))
            {
                if (input == null) throw new BrokerError("catalog_invalid");
                var value = (CatalogDocument)new DataContractJsonSerializer(typeof(CatalogDocument)).ReadObject(input);
                var names = new HashSet<string>(StringComparer.Ordinal);
                if (value.Schema != 1 || value.OperationApproval != OperationAuthorization.PromptStatus || value.Commands == null || value.Commands.Count != 47 || !Target.Hex(value.Hash, 64)) throw new BrokerError("catalog_invalid");
                foreach (CatalogEntry entry in value.Commands)
                {
                    if (entry == null || !Regex.IsMatch(entry.Name ?? "", "^[A-Za-z][A-Za-z0-9]+$") || !names.Add(entry.Name) ||
                        String.IsNullOrEmpty(entry.Gate) || String.IsNullOrEmpty(entry.Syntax) || String.IsNullOrEmpty(entry.Live) ||
                        Array.IndexOf(new[] { "no", "required", "depends" }, entry.Guest) < 0 || Array.IndexOf(new[] { "native-vix", "native-vix-helper", "official-vmrun-cli", "official-vmcli-cli", "official-https", "unsupported", "policy-locked" }, entry.Backend) < 0 ||
                        Array.IndexOf(new[] { "implemented", "partial", "deferred", "policy-locked" }, entry.State) < 0) throw new BrokerError("catalog_invalid");
                    if (entry.Enabled && (entry.Backend == "native-vix" || entry.Backend == "native-vix-helper") && (entry.Guest != NativePlans.GuestCategory(entry.Name) || entry.NeedsDisposable != NativePlans.Disposable(entry.Name) || entry.SensitiveRisk == NativePlans.MetadataOnly(entry.Name) ||
                        NativePlans.Symbol(new VmrunRequest { Entry = entry }) != entry.Exports.Split(',')[0])) throw new BrokerError("catalog_invalid");
                    if (entry.Enabled && entry.Backend == "native-vix-helper" && !GuestFixture.Command(entry.Name)) throw new BrokerError("catalog_invalid");
                    if (entry.Enabled && entry.Backend == "official-https" && (entry.Name != "downloadPhotonVM" || entry.NeedsCredential || entry.TargetScoped)) throw new BrokerError("catalog_invalid");
                    if (entry.Enabled && entry.Backend != "native-vix" && entry.Backend != "native-vix-helper" && entry.Backend != "official-https" && (!CliCommand(entry.Name) || entry.NeedsCredential || !entry.SensitiveRisk || entry.NeedsDisposable != CliDisposable(entry.Name) || entry.Backend != (entry.Name == "captureScreen" ? "official-vmcli-cli" : "official-vmrun-cli"))) throw new BrokerError("catalog_invalid");
                }
                return value;
            }
        }
        internal static bool CliCommand(string name) { return name == "getGuestIPAddress" || name == "listHostNetworks" || name == "listPortForwardings" || name == "captureScreen" || name == "connectNamedDevice" || name == "disconnectNamedDevice" || name == "removeSharedFolder" || name == "disableSharedFolders" || name == "upgradevm" || OwnedForwarding.Command(name); }
        internal static bool CliDisposable(string name) { return name == "captureScreen" || name == "connectNamedDevice" || name == "disconnectNamedDevice" || name == "removeSharedFolder" || name == "disableSharedFolders" || name == "upgradevm"; }
        internal static CatalogEntry Find(string name)
        {
            foreach (CatalogEntry entry in document.Commands) if (entry.Name == name) return entry;
            throw new BrokerError("invalid_request");
        }
        internal static List<string> CommandsFromHelp(string text)
        {
            var result = new List<string>();
            foreach (string line in text.Split('\n'))
            {
                if (line.StartsWith("Examples:", StringComparison.Ordinal)) break;
                Match match = Regex.Match(line, @"^([A-Za-z][A-Za-z0-9]+)\s{2,}\S");
                if (match.Success) result.Add(match.Groups[1].Value);
            }
            return result;
        }
    }

    internal sealed class VmrunRequest
    {
        internal CatalogEntry Entry;
        internal string TargetName;
        internal string[] Arguments;
        internal bool Stored;
        internal bool IsPublicVariable { get { return (Entry.Name == "readVariable" || Entry.Name == "writeVariable") && Arguments != null && Arguments.Length >= 2 && Arguments[0] == "guestVar"; } }
        internal bool IsApprovedListing { get { return Entry.Name == "listDirectoryInGuest" && Arguments != null && Arguments.Length == 3 && Arguments[2] == "--approved"; } }
        internal bool IsFixtureStart { get { return Entry.Name == "runProgramInGuest" && Arguments != null && Arguments.Length > 0 && Arguments[0] == "BROKER_PUBLIC_FIXTURE"; } }
        internal bool IsGeneratedFixture { get { return Entry.Name == "CreateTempfileInGuest" && Arguments != null && Arguments.Length == 4 && Arguments[2] == "--generated"; } }
        private string generatedId;
        internal string GeneratedId { get { if (generatedId == null) generatedId = Guid.NewGuid().ToString("N").ToUpperInvariant(); return generatedId; } }
        internal bool NeedsCredential { get { return Entry.Name == "readVariable" ? !IsPublicVariable : Entry.NeedsCredential; } }
        internal static VmrunRequest Parse(string[] tokens)
        {
            if (tokens.Length == 0) throw new BrokerError("invalid_request");
            CatalogEntry entry = Catalog.Find(tokens[0]);
            var args = new List<string>();
            for (int i = 1; i < tokens.Length; i++)
            {
                string item = tokens[i];
                if (item == null || item.Length > 4096 || item.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0) throw new BrokerError("invalid_request");
                foreach (char c in item) if (Char.IsControl(c)) throw new BrokerError("invalid_request");
                try { new UTF8Encoding(false, true).GetByteCount(item); } catch (ArgumentException) { throw new BrokerError("invalid_request"); }
                args.Add(item);
            }
            bool host = entry.Name == "listHostNetworks" || entry.Name == "listPortForwardings" || entry.Name == "setPortForwarding" || entry.Name == "deletePortForwarding" || entry.Name == "downloadPhotonVM" || entry.Name == "list";
            var request = new VmrunRequest { Entry = entry };
            if (!host)
            {
                if (args.Count == 0 || !Target.ValidName(args[0])) throw new BrokerError("invalid_request");
                request.TargetName = args[0]; args.RemoveAt(0);
            }
            if (entry.Name == "runProgramInGuest")
            {
                if (args.Count > 0 && (args[0] == "-noWait" || args[0] == "-activeWindow" || args[0] == "-interactive")) throw new BrokerError("unsupported_operation_option");
                if (args.Count < 2 || !Target.ValidName(args[0])) throw new BrokerError("invalid_request");
                int separator = 1;
                if (args[1] == "--stored") { request.Stored = true; separator++; }
                if (separator >= args.Count || args[separator] != "--") throw new BrokerError("unsupported_operation_option");
                string alias = args[0]; args.RemoveRange(0, separator + 1); args.Insert(0, alias);
                if (args.Count > 17 || String.Join("", args.ToArray()).Length > 8192) throw new BrokerError("invalid_request");
                for (int i = 1; i < args.Count; i++)
                {
                    string flag = args[i].ToLowerInvariant();
                    if (flag == "-gp" || flag == "-gu" || flag == "-vp" || flag.Contains("password") || flag.Contains("secret") || flag.Contains("token=")) throw new BrokerError("secret_argument_forbidden");
                }
            }
            else
            {
                if (args.Count > 0 && args[args.Count - 1] == "--stored" && (entry.Name == "listProcessesInGuest" || entry.Name == "readVariable" || entry.Name == "runScriptInGuest" || GuestFixture.Command(entry.Name) || PublicTransfers.Command(entry.Name)))
                { request.Stored = true; args.RemoveAt(args.Count - 1); }
                ValidateShape(entry.Name, args);
            }
            request.Arguments = args.ToArray();
            if (request.IsFixtureStart)
            {
                if (request.Arguments.Length != 3 || !FixtureProtocol.Alias(request.Arguments[1])) throw new BrokerError("invalid_request"); GuestProcessSupervisor.Slot(request.Arguments[2]);
            }
            return request;
        }
        private static void Count(List<string> args, int min, int max) { if (args.Count < min || args.Count > max) throw new BrokerError("invalid_request"); }
        private static void Choice(string value, params string[] options) { if (Array.IndexOf(options, value) < 0) throw new BrokerError("invalid_request"); }
        internal static void Label(string label)
        {
            if (String.IsNullOrWhiteSpace(label) || label.Length > 128 || label.Trim() != label) throw new BrokerError("invalid_request");
            foreach (char c in label) if (Char.IsControl(c) || c == '/' || c == '\\') throw new BrokerError("invalid_request");
        }
        private static void ValidateShape(string name, List<string> args)
        {
            switch (name)
            {
                case "start": Count(args, 1, 1); Choice(args[0], "gui", "nogui"); break;
                case "stop": case "reset": case "suspend": Count(args, 1, 1); Choice(args[0], "hard", "soft"); break;
                case "pause": case "unpause": case "listProcessesInGuest": case "list": case "upgradevm": case "installTools": case "checkToolsState": case "deleteVM": case "listHostNetworks": Count(args, 0, 0); break;
                case "listSnapshots": Count(args, 0, 1); if (args.Count != 0) Choice(args[0], "showTree"); break;
                case "snapshot": case "revertToSnapshot": Count(args, 1, 1); Label(args[0]); break;
                case "deleteSnapshot": Count(args, 1, 2); Label(args[0]); if (args.Count == 2) Choice(args[1], "andDeleteChildren"); break;
                case "enableSharedFolders": case "disableSharedFolders": Count(args, 0, 1); if (args.Count != 0) Choice(args[0], "runtime"); break;
                case "captureScreen": Count(args, 0, 0); break;
                case "listPortForwardings": Count(args, 1, 1); CliParsing.NetworkName(args[0]); break;
                case "connectNamedDevice": case "disconnectNamedDevice": Count(args, 1, 1); DeviceBinding.Id(args[0]); break;
                case "removeSharedFolder": Count(args, 1, 1); Label(args[0]); break;
                case "listDirectoryInGuest": Count(args, 2, 3); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); FixtureProtocol.Relative(args[1]); if (args.Count == 3) Choice(args[2], "--approved"); break;
                case "CreateTempfileInGuest": Count(args, 2, 4); if (args.Count != 2 && (args.Count != 4 || args[2] != "--generated")) throw new BrokerError("invalid_request"); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); FixtureProtocol.Relative(args[1]); if (args.Count == 4) GeneratedFixture.Size(args[3]); break;
                case "fileExistsInGuest": case "directoryExistsInGuest": case "createDirectoryInGuest": case "deleteFileInGuest": case "deleteDirectoryInGuest": Count(args, 2, 2); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); FixtureProtocol.Relative(args[1]); break;
                case "killProcessInGuest": Count(args, 2, 2); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); GuestProcessSupervisor.Slot(args[1]); break;
                case "typeKeystrokesInGuest": Count(args, 3, 3); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); GuestProcessSupervisor.Slot(args[1]); PublicFixtureSink.SampleName(args[2]); break;
                case "downloadPhotonVM": Count(args, 1, 1); Choice(args[0], "photon5"); break;
                case "renameFileInGuest": Count(args, 3, 3); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("guest_fixture_path_rejected"); GuestRename.Destination(args[1], args[2]); break;
                case "CopyFileFromHostToGuest":
                    Count(args, 2, 2); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("transfer_request_invalid"); GeneratedFixture.Size(args[1]); break;
                case "CopyFileFromGuestToHost":
                    Count(args, 3, 3); if (!FixtureProtocol.Alias(args[0]) || !FixtureProtocol.Hex(args[1], 32)) throw new BrokerError("transfer_request_invalid"); GeneratedFixture.Size(args[2]); break;
                case "addSharedFolder": Count(args, 1, 1); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("public_share_not_approved"); break;
                case "setSharedFolderState": Count(args, 2, 2); if (!FixtureProtocol.Alias(args[0])) throw new BrokerError("public_share_not_approved"); Choice(args[1], "writable", "readonly"); break;
                case "readVariable":
                    Count(args, 2, 2); Choice(args[0], "runtimeConfig", "guestEnv", "guestVar");
                    if (args[0] == "guestVar" && !PublicVariable.ValidAlias(args[1])) throw new BrokerError("invalid_request"); break;
                case "writeVariable":
                    Count(args, 3, 3); Choice(args[0], "runtimeConfig", "guestEnv", "guestVar");
                    if (args[0] == "guestVar") { if (!PublicVariable.ValidAlias(args[1])) throw new BrokerError("invalid_request"); PublicScalar.Parse(args[2]); } break;
                case "getGuestIPAddress": Count(args, 0, 1); if (args.Count != 0) Choice(args[0], "-wait"); break;
                case "setPortForwarding": Count(args, 5, 6); CliParsing.NetworkName(args[0]); Choice(args[1], "tcp"); OwnedForwarding.CanonicalPort(args[2], true); ForwardPolicy.PrivateAddress(args[3]); OwnedForwarding.CanonicalPort(args[4], false); if (args.Count == 6 && !Regex.IsMatch(args[5], @"^broker-temporary-[A-F0-9]{32}$")) throw new BrokerError("forward_scope_refused"); break;
                case "deletePortForwarding": Count(args, 3, 3); CliParsing.NetworkName(args[0]); Choice(args[1], "tcp"); OwnedForwarding.CanonicalPort(args[2], true); break;
                case "runScriptInGuest":
                    if (args.Count > 0 && (args[0] == "-noWait" || args[0] == "-activeWindow" || args[0] == "-interactive")) throw new BrokerError("unsupported_operation_option");
                    Count(args, 1, 1); if (!Target.ValidName(args[0])) throw new BrokerError("invalid_request"); break;
                case "clone":
                    Count(args, 1, 1); Choice(args[0], "full"); break;
                default: throw new BrokerError("invalid_request");
            }
        }
        internal string[] Tokens()
        {
            var tokens = new List<string>(); tokens.Add(Entry.Name); if (TargetName != null) tokens.Add(TargetName);
            if (Entry.Name == "runProgramInGuest")
            { tokens.Add(Arguments[0]); if (Stored) tokens.Add("--stored"); tokens.Add("--"); for (int i = 1; i < Arguments.Length; i++) tokens.Add(Arguments[i]); }
            else { tokens.AddRange(Arguments); if (Stored) tokens.Add("--stored"); }
            return tokens.ToArray();
        }
        internal bool EnabledVariant
        {
            get
            {
                if (!Entry.Enabled) return false;
                if (Entry.Name == "readVariable") return (Arguments[0] == "guestEnv" && Arguments[1] == "COMPUTERNAME") || (IsPublicVariable && !Stored);
                if (Entry.Name == "writeVariable") return IsPublicVariable;
                return true;
            }
        }
    }
}
