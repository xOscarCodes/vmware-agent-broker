using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace GuestBroker
{
    [DataContract]
    internal sealed class PublicFixtureEntry
    {
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal string Name { get; set; }
        [DataMember(IsRequired = true)] internal string Kind { get; set; }
        internal void Validate()
        {
            if (!FixtureProtocol.Alias(Alias) || (Kind != "file" && Kind != "directory")) throw new BrokerError("guest_fixture_listing_refused");
            if (FixtureProtocol.Relative(Name).Contains("\\")) throw new BrokerError("guest_fixture_path_rejected");
        }
    }
    [DataContract]
    internal sealed class ApprovedListing
    {
        internal const int Maximum = 8, ExitBase = 0x100000;
        [DataMember(IsRequired = true)] internal string Directory { get; set; }
        [DataMember(IsRequired = true)] internal List<PublicFixtureEntry> Entries { get; set; }
        internal void Validate()
        {
            if (Entries == null || Entries.Count < 1 || Entries.Count > Maximum) throw new BrokerError("guest_fixture_listing_refused");
            FixtureProtocol.Relative(Directory);
            ValidateEntries(Entries);
        }
        internal static void ValidateEntries(List<PublicFixtureEntry> entries)
        {
            if (entries == null || entries.Count > Maximum) throw new BrokerError("guest_fixture_listing_refused");
            var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PublicFixtureEntry entry in entries)
            {
                if (entry == null) throw new BrokerError("guest_fixture_listing_refused"); entry.Validate();
                if (!aliases.Add(entry.Alias) || !names.Add(entry.Name)) throw new BrokerError("guest_fixture_listing_refused");
            }
        }
        internal List<PublicFixtureEntry> Ordered()
        {
            Validate(); var entries = new List<PublicFixtureEntry>(Entries);
            entries.Sort(delegate(PublicFixtureEntry a, PublicFixtureEntry b) { return StringComparer.Ordinal.Compare(a.Alias, b.Alias); }); return entries;
        }
        internal string[] Lines()
        {
            var lines = new List<string>(); foreach (PublicFixtureEntry entry in Ordered()) lines.Add(Directory + "|" + entry.Alias + "|" + entry.Name + "|" + entry.Kind); return lines.ToArray();
        }
        internal string Digest()
        {
            string canonical = "P4-APPROVED-NAMES-V1\n" + String.Join("\n", Lines()) + "\n";
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(canonical))).Replace("-", "");
        }
        internal static ApprovedListing ParseLines(IEnumerable<string> lines)
        {
            var plan = new ApprovedListing { Entries = new List<PublicFixtureEntry>() };
            foreach (string line in lines)
            {
                if (String.IsNullOrWhiteSpace(line)) continue;
                string[] fields = line.Split('|');
                if (fields.Length != 4 || plan.Entries.Count >= Maximum || (plan.Directory != null && plan.Directory != fields[0])) throw new BrokerError("guest_fixture_listing_refused");
                plan.Directory = fields[0]; plan.Entries.Add(new PublicFixtureEntry { Alias = fields[1], Name = fields[2], Kind = fields[3] });
            }
            plan.Validate(); return plan;
        }
        internal int Decode(long status)
        {
            Validate(); int bound = 1 << Entries.Count;
            if (status < ExitBase || status >= ExitBase + bound) throw new BrokerError("guest_fixture_listing_refused"); return (int)(status - ExitBase);
        }
        internal List<PublicFixtureEntry> Result(long status)
        {
            int mask = Decode(status); var result = new List<PublicFixtureEntry>(); List<PublicFixtureEntry> ordered = Ordered();
            for (int i = 0; i < ordered.Count; i++) if ((mask & (1 << i)) != 0)
                result.Add(new PublicFixtureEntry { Alias = ordered[i].Alias, Name = ordered[i].Name, Kind = ordered[i].Kind });
            return result; // Only enrolled host strings, never strings returned by guest code.
        }
        internal void Demand(string relative)
        {
            Validate(); if (relative != Directory) throw new BrokerError("guest_fixture_listing_refused");
        }
    }
}
