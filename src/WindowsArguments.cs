using System;
using System.Collections.Generic;
using System.Text;

namespace GuestBroker
{
    internal static class WindowsArguments
    {
        internal static string Quote(string value)
        {
            if (value == null || value.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0) throw new BrokerError("invalid_request");
            var text = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                text.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; text.Append(c);
            }
            return text.Append('\\', slashes * 2).Append('"').ToString();
        }
        internal static string Join(IEnumerable<string> args)
        {
            var values = new List<string>(); foreach (string arg in args) values.Add(Quote(arg));
            string result = String.Join(" ", values.ToArray()); if (result.Length > 16384) throw new BrokerError("invalid_request"); return result;
        }
    }
}
