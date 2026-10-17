using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace GuestBroker
{
    [DataContract]
    internal sealed class PublicVariable
    {
        internal const string Prefix = "vmware_guest_broker.public.";
        [DataMember(IsRequired = true)] internal string Alias { get; set; }
        [DataMember(IsRequired = true)] internal string Kind { get; set; }
        [DataMember(IsRequired = true)] internal int Minimum { get; set; }
        [DataMember(IsRequired = true)] internal int Maximum { get; set; }
        [DataMember(IsRequired = true)] internal bool Read { get; set; }
        [DataMember(IsRequired = true)] internal bool Write { get; set; }
        internal string NativeName { get { Validate(); return Prefix + Alias; } }
        internal static bool ValidAlias(string alias) { return Regex.IsMatch(alias ?? "", @"^[A-Za-z][A-Za-z0-9_-]{0,31}$", RegexOptions.CultureInvariant); }
        internal void Validate()
        {
            if (!ValidAlias(Alias) || (!Read && !Write) || (Kind != "int32" && Kind != "bool") || (Kind == "int32" && Minimum > Maximum) || (Kind == "bool" && (Minimum != 0 || Maximum != 0))) throw new BrokerError("public_variable_policy_invalid");
            string name = Alias.ToLowerInvariant();
            foreach (string secret in new[] { "password", "passwd", "token", "secret", "credential", "privatekey" }) if (name.Contains(secret)) throw new BrokerError("public_variable_policy_invalid");
        }
        internal void Check(PublicScalar value)
        {
            Validate();
            if (value == null || value.Kind != Kind || (Kind == "int32" && (!value.Integer.HasValue || value.Boolean.HasValue || value.Integer < Minimum || value.Integer > Maximum)) ||
                (Kind == "bool" && (!value.Boolean.HasValue || value.Integer.HasValue))) throw new BrokerError("public_variable_value_rejected");
        }
        internal static PublicVariable PolicyLine(string line)
        {
            string[] parts = line.Split('|');
            if (parts.Length != 3 && parts.Length != 5) throw new BrokerError("public_variable_policy_invalid");
            var value = new PublicVariable { Alias = parts[0], Kind = parts[1] };
            string rights = parts[parts.Length - 1];
            if (rights != "r" && rights != "w" && rights != "rw") throw new BrokerError("public_variable_policy_invalid");
            value.Read = rights.Contains("r"); value.Write = rights.Contains("w");
            if (value.Kind == "int32" && parts.Length == 5)
            {
                PublicScalar low = PublicScalar.Parse(parts[2]), high = PublicScalar.Parse(parts[3]);
                if (low.Kind != "int32" || high.Kind != "int32") throw new BrokerError("public_variable_policy_invalid");
                value.Minimum = low.Integer.Value; value.Maximum = high.Integer.Value;
            }
            else if (value.Kind != "bool" || parts.Length != 3) throw new BrokerError("public_variable_policy_invalid");
            value.Validate(); return value;
        }
        internal string PolicyLine()
        {
            Validate(); return Alias + "|" + Kind + (Kind == "int32" ? "|" + Minimum.ToString(CultureInfo.InvariantCulture) + "|" + Maximum.ToString(CultureInfo.InvariantCulture) : "") + "|" + (Read ? "r" : "") + (Write ? "w" : "");
        }
    }
    internal sealed class PublicScalar
    {
        internal string Kind;
        internal int? Integer;
        internal bool? Boolean;
        internal static PublicScalar Parse(string text)
        {
            if (text == "true" || text == "false") return new PublicScalar { Kind = "bool", Boolean = text == "true" };
            int number;
            if (text == null || text.Length < 1 || text.Length > 11 || !Int32.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number) || number.ToString(CultureInfo.InvariantCulture) != text)
                throw new BrokerError("public_variable_value_rejected");
            return new PublicScalar { Kind = "int32", Integer = number };
        }
        internal string Text { get { return Kind == "bool" ? (Boolean.Value ? "true" : "false") : Integer.Value.ToString(CultureInfo.InvariantCulture); } }
        internal static PublicScalar FromNative(IntPtr pointer, PublicVariable policy)
        {
            policy.Validate(); if (pointer == IntPtr.Zero) throw new BrokerError("public_variable_value_rejected");
            if (policy.Kind == "bool")
            {
                bool? value = Literal(pointer, "true") ? true : Literal(pointer, "false") ? (bool?)false : null;
                if (!value.HasValue) throw new BrokerError("public_variable_value_rejected");
                return new PublicScalar { Kind = "bool", Boolean = value };
            }
            // Do not construct or log a managed raw guest-value string. At most
            // eleven ASCII scalar bytes are inspected; arbitrary native values
            // (including strings a guest placed under our key) are never returned.
            long magnitude = 0; int count = 0, digits = 0; bool negative = false;
            for (; count < 12; count++)
            {
                byte c = Marshal.ReadByte(pointer, count);
                if (c == 0) break;
                if (count == 0 && c == '-') { negative = true; continue; }
                if (c < '0' || c > '9' || digits >= 10) throw new BrokerError("public_variable_value_rejected");
                if (digits > 0 && magnitude == 0) throw new BrokerError("public_variable_value_rejected");
                magnitude = magnitude * 10 + c - '0'; digits++;
            }
            long signed = negative ? -magnitude : magnitude;
            if (count >= 12 || count == 0 || digits == 0 || (negative && magnitude == 0) || signed < Int32.MinValue || signed > Int32.MaxValue) throw new BrokerError("public_variable_value_rejected");
            var result = new PublicScalar { Kind = "int32", Integer = (int)signed }; policy.Check(result); return result;
        }
        private static bool Literal(IntPtr pointer, string value)
        {
            for (int i = 0; i < value.Length; i++) if (Marshal.ReadByte(pointer, i) != value[i]) return false;
            return Marshal.ReadByte(pointer, value.Length) == 0;
        }
    }
}
