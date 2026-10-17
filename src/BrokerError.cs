using System;

namespace GuestBroker
{
    internal sealed class BrokerError : Exception
    {
        internal readonly string Code;
        internal BrokerError(string code) { Code = code; Diagnostics.Fault(); }
    }
}
