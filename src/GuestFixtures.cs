using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;

namespace GuestBroker
{
    [DataContract]
    internal sealed class GuestFixture
    {
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal string EnrollmentId { get; set; }
        [DataMember(IsRequired = true)] internal string HelperPath { get; set; }
        [DataMember(IsRequired = true)] internal string ImageSha256 { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool OwnedMutations { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool PublicListing { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool OwnedRenames { get; set; }
        [DataMember(EmitDefaultValue = false)] internal ApprovedListing ApprovedListing { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool OwnedDeletes { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool OwnedProcesses { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool GeneratedFixtures { get; set; }
        [DataMember(EmitDefaultValue = false)] internal bool OwnedSink { get; set; }
        internal void Validate()
        {
            if (!FixtureProtocol.Alias(Alias) || !FixtureProtocol.Hex(EnrollmentId, 32) || !CapabilityProfile.ValidProgramPath(HelperPath) || !HelperPath.EndsWith("\\broker-guest-helper.exe", StringComparison.OrdinalIgnoreCase) || !FixtureProtocol.Hex(ImageSha256, 64))
                throw new BrokerError("guest_fixture_policy_invalid");
            if (ApprovedListing != null) ApprovedListing.Validate();
        }
        internal string Arguments(Target target, VmrunRequest request)
        {
            DemandImage(request);
            if (request.IsFixtureStart || ProcessStop(request.Entry.Name) || ProcessType(request.Entry.Name))
            {
                if (!OwnedProcesses || RootAlias(request) != Alias) throw new BrokerError("guest_fixture_process_refused");
                string slot = request.IsFixtureStart ? request.Arguments[2] : request.Arguments[1]; GuestProcessSupervisor.Slot(slot);
                if (ProcessType(request.Entry.Name))
                {
                    if (!OwnedSink) throw new BrokerError("guest_fixture_process_refused"); PublicFixtureSink.SampleName(request.Arguments[2]);
                    return WindowsArguments.Join(new[] { "type-owned-fixture", target.Binding, Alias, EnrollmentId, ImageSha256, slot, request.Arguments[2] });
                }
                return WindowsArguments.Join(new[] { request.IsFixtureStart ? "start-owned-process" : "stop-owned-process", target.Binding, Alias, EnrollmentId, ImageSha256, slot });
            }
            if (request.Arguments.Length != (request.IsGeneratedFixture ? 4 : Rename(request.Entry.Name) || request.IsApprovedListing ? 3 : 2) || request.Arguments[0] != Alias) throw new BrokerError("guest_fixture_not_approved");
            string operation = request.IsGeneratedFixture ? "create-generated-file" : request.IsApprovedListing ? "list-approved" : Operation(request.Entry.Name);
            if (GuestOwned.Operation(operation) && !OwnedMutations) throw new BrokerError("guest_fixture_owned_refused");
            if (request.IsApprovedListing) NamedPlan(request.Arguments[1]);
            else if (Listing(request.Entry.Name) && !PublicListing) throw new BrokerError("guest_fixture_listing_refused");
            if (Rename(request.Entry.Name) && !OwnedRenames) throw new BrokerError("guest_fixture_owned_refused");
            if (Delete(request.Entry.Name) && !OwnedDeletes) throw new BrokerError("guest_fixture_owned_refused");
            var args = new List<string> { operation, target.Binding, Alias, EnrollmentId, ImageSha256, FixtureProtocol.Relative(request.Arguments[1]) };
            if (Rename(request.Entry.Name)) { GuestRename.Destination(request.Arguments[1], request.Arguments[2]); args.Add(request.Arguments[2]); }
            if (request.IsApprovedListing) args.Add(ApprovedListing.Digest());
            if (request.IsGeneratedFixture) { if (!GeneratedFixtures) throw new BrokerError("guest_fixture_owned_refused"); args.Add(request.Arguments[3]); args.Add(request.GeneratedId); }
            return WindowsArguments.Join(args);
        }
        internal void DemandImage(VmrunRequest request)
        {
            Validate(); if (ImageSha256 == HelperBuild.Hash) return;
            // Exact parent-reviewed protocol3 image, actually hash-verified in
            // guest. Compatibility is deliberately limited to unchanged old ops.
            bool legacy = ImageSha256 == "4FBF8C7B98936992E79215DECDE57FF7EBDE770D675E9CC48FB914ED8C350D23";
            string name = request.Entry.Name;
            // Exact prior utility delivery images, not any protocol4 executable.
            // Guest opcodes/optional rights have not changed for these operations;
            // host-only exit/CLI/clone fixes must not force a new guest enrollment.
            bool known4 = ImageSha256 == "6EC73F9E903FF33F53E37CEB592EE174999B701F2B21E05A97E076E31EAB13F0" || ImageSha256 == "0D2B91BAA4B953ACEABF21CE3A384BFCD4F17EC99CED6EF89D28CD932774191D" || ImageSha256 == "3427B41616CC342A6E788ABE2CCF64FE228BD67887383D388136A45E433F530D" || ImageSha256 == "95305E6C598796BD5B88C8621AA0FD8614F54C2FA8339186206D8A59BBE935A9" || ImageSha256 == "F6E0EC1062D8B0A5FC7FF3ED6B8931A5B2031D2019EF86BB15B968BB39113D74" || ImageSha256 == "80A4826BE193B71CF20D1E0A82BB8B6D860040BB828953EB4456F70E0C0C32CC" || ImageSha256 == "1F2D9A04D7770E51B4D48FC4198FBCA193D273DBD0382A0F6A053E4463D0B16D" || ImageSha256 == "E25F52F36F2DD43D1549135EEA521312ADC67A4792A234CBE6EE858ED1837669" || ImageSha256 == "769878A1AE3ADA8964365AB53EF58E973187CCAB97169DF6EC495D5DD6FA44E4";
            if (known4 && (request.IsFixtureStart || Array.IndexOf(new[] { "fileExistsInGuest", "directoryExistsInGuest", "listDirectoryInGuest", "createDirectoryInGuest", "CreateTempfileInGuest", "renameFileInGuest", "deleteFileInGuest", "deleteDirectoryInGuest", "killProcessInGuest", "typeKeystrokesInGuest" }, name) >= 0)) return;
            if (legacy && !request.IsApprovedListing && !request.IsGeneratedFixture && (name == "fileExistsInGuest" || name == "directoryExistsInGuest" || name == "listDirectoryInGuest" || name == "createDirectoryInGuest" || name == "CreateTempfileInGuest")) return;
            throw new BrokerError("guest_fixture_image_unavailable");
        }
        internal ApprovedListing NamedPlan(string directory)
        {
            if (ApprovedListing == null) throw new BrokerError("guest_fixture_listing_refused"); ApprovedListing.Demand(directory); return ApprovedListing;
        }
        internal static void CompleteApproved(OperationReport result, string alias, ApprovedListing plan, long status)
        {
            if (!Listing(result.Command) || plan == null) throw new BrokerError("guest_fixture_listing_refused");
            result.ApprovedEntries = plan.Result(status); result.Count = result.ApprovedEntries.Count; result.Fixture = alias; result.Completion = "guest_fixture_approved_listing_observation";
        }
        internal static void AttachNamedPlans(List<GuestFixture> fixtures, IEnumerable<string> lines)
        {
            var groups = new Dictionary<string, List<string>>(StringComparer.Ordinal); int count = 0;
            foreach (string line in lines)
            {
                if (String.IsNullOrWhiteSpace(line)) continue;
                int split = line.IndexOf('|'); if (split < 1 || ++count > 64) throw new BrokerError("guest_fixture_listing_refused");
                string alias = line.Substring(0, split);
                if (fixtures == null || !fixtures.Exists(delegate (GuestFixture fixture) { return fixture.Alias == alias; })) throw new BrokerError("guest_fixture_not_approved");
                List<string> group; if (!groups.TryGetValue(alias, out group)) { group = new List<string>(); groups.Add(alias, group); }
                group.Add(line.Substring(split + 1));
            }
            var plans = new Dictionary<string, ApprovedListing>(StringComparer.Ordinal);
            foreach (var group in groups) plans.Add(group.Key, GuestBroker.ApprovedListing.ParseLines(group.Value));
            if (fixtures != null) foreach (GuestFixture fixture in fixtures) { ApprovedListing plan; fixture.ApprovedListing = plans.TryGetValue(fixture.Alias, out plan) ? plan : null; }
        }
        internal static bool Command(string name) { return name == "fileExistsInGuest" || name == "directoryExistsInGuest" || Mutation(name) || Listing(name); }
        internal static bool RequestIsHelper(VmrunRequest request) { return Command(request.Entry.Name) || request.IsFixtureStart; }
        internal static string RootAlias(VmrunRequest request) { return request.IsFixtureStart ? request.Arguments[1] : request.Arguments[0]; }
        internal static bool ProcessStop(string name) { return name == "killProcessInGuest"; }
        internal static bool ProcessType(string name) { return name == "typeKeystrokesInGuest"; }
        internal static bool Listing(string name) { return name == "listDirectoryInGuest"; }
        internal static bool Rename(string name) { return name == "renameFileInGuest"; }
        internal static bool Delete(string name) { return name == "deleteFileInGuest" || name == "deleteDirectoryInGuest"; }
        internal static bool Mutation(string name) { return name == "createDirectoryInGuest" || name == "CreateTempfileInGuest" || Rename(name) || Delete(name) || ProcessStop(name) || ProcessType(name); }
        internal static string Operation(string name)
        {
            switch (name)
            {
                case "fileExistsInGuest": return "probe-file";
                case "directoryExistsInGuest": return "probe-directory";
                case "createDirectoryInGuest": return "create-directory";
                case "CreateTempfileInGuest": return "create-empty-file";
                case "listDirectoryInGuest": return "list-counts";
                case "renameFileInGuest": return "rename-owned-file";
                case "deleteFileInGuest": return "delete-owned-file";
                case "deleteDirectoryInGuest": return "delete-owned-tree";
                case "killProcessInGuest": return "stop-owned-process";
                case "typeKeystrokesInGuest": return "type-owned-fixture";
                default: throw new BrokerError("guest_fixture_policy_invalid");
            }
        }
        internal static void Complete(OperationReport result, string alias, long status)
        {
            if (Listing(result.Command))
            {
                ListingCounts counts = ListingCounts.Decode(status);
                result.Fixture = alias; result.FixtureFiles = counts.Files; result.FixtureDirectories = counts.Directories;
                result.Count = counts.Files + counts.Directories; result.Completion = "guest_fixture_listing_observation";
            }
            else if (Mutation(result.Command))
            {
                if (status == FixtureProtocol.Invalid || status == FixtureProtocol.RootChanged || status == FixtureProtocol.Redirected || status == FixtureProtocol.NotEnrolled || status == FixtureProtocol.ImageChanged || status == FixtureProtocol.MutationRefused) throw new BrokerError("guest_fixture_helper_refused");
                if (status != 0) throw new BrokerError("guest_fixture_mutation_uncertain");
                result.Fixture = alias; result.FixtureAction = Operation(result.Command); result.Completion = "guest_fixture_mutation_ack";
            }
            else
            {
                if (status != FixtureProtocol.Exists && status != FixtureProtocol.Missing) throw new BrokerError("guest_fixture_helper_refused");
                result.Fixture = alias; result.Exists = status == FixtureProtocol.Exists; result.Completion = "guest_fixture_observation";
            }
        }
        internal static void CompleteProcess(OperationReport result, VmrunRequest request, string alias, long status)
        {
            if (!request.IsFixtureStart && !ProcessStop(request.Entry.Name) && !ProcessType(request.Entry.Name)) throw new BrokerError("guest_fixture_process_refused");
            if (status == FixtureProtocol.Invalid || status == FixtureProtocol.RootChanged || status == FixtureProtocol.Redirected || status == FixtureProtocol.NotEnrolled || status == FixtureProtocol.ImageChanged || status == FixtureProtocol.MutationRefused) throw new BrokerError("guest_fixture_helper_refused");
            if (status != 0) throw new BrokerError("guest_fixture_mutation_uncertain");
            result.Fixture = alias; result.FixtureProcessSlot = request.IsFixtureStart ? request.Arguments[2] : request.Arguments[1];
            result.FixtureAction = request.IsFixtureStart ? "start-owned-process" : ProcessType(request.Entry.Name) ? "type-owned-fixture" : "stop-owned-process"; result.Completion = "guest_fixture_process_ack";
        }
        internal static void CompleteGenerated(OperationReport result, VmrunRequest request, string alias, long status)
        {
            if (!request.IsGeneratedFixture) throw new BrokerError("guest_fixture_generated_refused");
            Complete(result, alias, status); result.FixtureAction = "create-generated-file"; result.FixtureGeneratedId = request.GeneratedId; result.FixtureGeneratedBytes = GeneratedFixture.Size(request.Arguments[3]);
        }
        internal string PolicyLine()
        {
            string flags = Flags(); return Alias + "|" + EnrollmentId + "|" + HelperPath + (flags.Length == 0 ? "" : "|" + flags);
        }
        private string Flags()
        {
            var flags = new List<string>(); if (OwnedMutations) flags.Add("owned-empty"); if (PublicListing) flags.Add("public-counts"); if (OwnedRenames) flags.Add("owned-rename"); if (OwnedDeletes) flags.Add("owned-delete"); if (OwnedProcesses) flags.Add("owned-process"); if (GeneratedFixtures) flags.Add("generated-fixture"); if (OwnedSink) flags.Add("owned-sink"); return String.Join(",", flags.ToArray());
        }
        internal static GuestFixture PolicyLine(string line)
        {
            string[] fields = line.Split('|');
            if (fields.Length != 3 && fields.Length != 4) throw new BrokerError("guest_fixture_policy_invalid");
            var result = new GuestFixture { Alias = fields[0], EnrollmentId = fields[1], HelperPath = fields[2], ImageSha256 = HelperBuild.Hash };
            if (fields.Length == 4)
            {
                string[] flags = fields[3].Split(',');
                foreach (string flag in flags)
                {
                    switch (flag)
                    {
                        case "owned-empty": result.OwnedMutations = true; break;
                        case "public-counts": result.PublicListing = true; break;
                        case "owned-rename": result.OwnedRenames = true; break;
                        case "owned-delete": result.OwnedDeletes = true; break;
                        case "owned-process": result.OwnedProcesses = true; break;
                        case "generated-fixture": result.GeneratedFixtures = true; break;
                        case "owned-sink": result.OwnedSink = true; break;
                        default: throw new BrokerError("guest_fixture_policy_invalid");
                    }
                }
                if (fields[3] != result.Flags()) throw new BrokerError("guest_fixture_policy_invalid");
            }
            return result;
        }
        internal static GuestFixture SetupLine(string line, List<GuestFixture> priorReceipts)
        {
            GuestFixture fixture = PolicyLine(line);
            if (priorReceipts != null)
            {
                GuestFixture prior = priorReceipts.Find(delegate (GuestFixture item) { return item.Alias == fixture.Alias && item.EnrollmentId == fixture.EnrollmentId && item.HelperPath == fixture.HelperPath; });
                if (prior != null) fixture.ImageSha256 = prior.ImageSha256;
            }
            return fixture;
        }
    }
    internal static class HelperBuild
    {
        private static readonly string hash = Load();
        internal static string Hash { get { return hash; } }
        private static string Load()
        {
            using (Stream input = typeof(HelperBuild).Assembly.GetManifestResourceStream("GuestBroker.HelperImageSha256"))
            {
                if (input == null) throw new BrokerError("guest_fixture_image_unavailable");
                using (var reader = new StreamReader(input))
                { string value = reader.ReadToEnd().Trim(); if (!FixtureProtocol.Hex(value, 64)) throw new BrokerError("guest_fixture_image_unavailable"); return value; }
            }
        }
    }
}
