using System;
using System.Runtime.InteropServices;

namespace GuestBroker
{
    internal static class GuestExitReader
    {
        internal const int Property = 3018;
        internal static int Width(int actualType)
        {
            // Public VIX enum: INTEGER=1 (int32), INT64=5. The installed
            // Vix_GetPropertyType result, not the property name, selects width.
            if (actualType == 1) return 4;
            if (actualType == 5) return 8;
            Diagnostics.PropertyMismatch(Property, "1_or_5", actualType);
            throw new BrokerError("vix_property_type_mismatch");
        }
        internal static long Read(int actualType, Action<IntPtr> readProperty)
        {
            int width = Width(actualType);
            IntPtr value = Marshal.AllocHGlobal(width);
            try
            {
                // Failed/unwritten native output cannot masquerade as zero.
                for (int i = 0; i < width; i++) Marshal.WriteByte(value, i, 0xff);
                readProperty(value);
                return width == 4 ? Marshal.ReadInt32(value) : Marshal.ReadInt64(value);
            }
            finally { Marshal.FreeHGlobal(value); }
        }
    }
}
