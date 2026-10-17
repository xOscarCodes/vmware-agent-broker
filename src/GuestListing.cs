using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static partial class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, IntPtr information, uint size);
    }
    internal sealed class ListingCounts
    {
        internal const int Maximum = 64, Base = 0x1000;
        internal int Files { get; private set; }
        internal int Directories { get; private set; }
        internal ListingCounts(int files, int directories)
        {
            if (files < 0 || directories < 0 || files > Maximum || directories > Maximum || files + directories > Maximum) throw new BrokerError("guest_fixture_listing_refused");
            Files = files; Directories = directories;
        }
        internal int Encode() { return Base + Files * (Maximum + 1) + Directories; }
        internal static ListingCounts Decode(long status)
        {
            if (status < Base || status > Base + Maximum * (Maximum + 1) + Maximum) throw new BrokerError("guest_fixture_listing_refused");
            int value = (int)(status - Base); return new ListingCounts(value / (Maximum + 1), value % (Maximum + 1));
        }
    }
    internal static class GuestListing
    {
        internal const int BufferBytes = 16384, NameOffset = 104, MaximumBatches = 4;
        private const uint AllowedAttributes = 0x1 | 0x10 | 0x20 | 0x80 | 0x100 | 0x200 | 0x800 | 0x2000;
        // Public FILE_ID_BOTH_DIR_INFO: the fixed fields and SHORT_NAME storage
        // place FileName at104, aligned to8. Only attributes/name are interpreted;
        // IDs/timestamps/sizes/short names are neither trusted nor returned.
        internal static void ParseBatch(IntPtr buffer, int length, Action<string, bool> entry)
        {
            if (buffer == IntPtr.Zero || length < NameOffset + 2 || length > BufferBytes) throw new BrokerError("guest_fixture_listing_refused");
            int offset = 0, entries = 0;
            while (true)
            {
                if (++entries > ListingCounts.Maximum + 2 || offset < 0 || offset > length - NameOffset - 2 || offset % 8 != 0) throw new BrokerError("guest_fixture_listing_refused");
                int next = Marshal.ReadInt32(buffer, offset), nameBytes = Marshal.ReadInt32(buffer, offset + 60);
                uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 56));
                if (nameBytes < 2 || nameBytes > 96 || nameBytes % 2 != 0 || nameBytes > length - offset - NameOffset ||
                    (next != 0 && (next < NameOffset + nameBytes || next % 8 != 0 || next > length - offset - NameOffset - 2))) throw new BrokerError("guest_fixture_listing_refused");
                string name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + NameOffset), nameBytes / 2);
                if (name != "." && name != "..")
                {
                    if (FixtureProtocol.Relative(name).Contains("\\")) throw new BrokerError("guest_fixture_path_rejected");
                    if (attributes == 0 || (attributes & ~AllowedAttributes) != 0) throw new BrokerError("guest_fixture_listing_refused");
                    entry(name, (attributes & 0x10) != 0);
                }
                if (next == 0) return;
                offset += next;
            }
        }
        internal static void VisitDirectory(SafeFileHandle directory, Action<string, bool> entry)
        {
            IntPtr buffer = Marshal.AllocHGlobal(BufferBytes);
            try
            {
                for (int batch = 0; batch < MaximumBatches; batch++)
                {
                    for (int i = 0; i < BufferBytes; i++) Marshal.WriteByte(buffer, i, 0);
                    if (!Native.GetFileInformationByHandleEx(directory, batch == 0 ? 11 : 10, buffer, BufferBytes))
                    { if (Marshal.GetLastWin32Error() == 18) return; throw new BrokerError("guest_fixture_listing_refused"); }
                    ParseBatch(buffer, BufferBytes, entry);
                }
                throw new BrokerError("guest_fixture_listing_refused");
            }
            finally { for (int i = 0; i < BufferBytes; i++) Marshal.WriteByte(buffer, i, 0); Marshal.FreeHGlobal(buffer); }
        }
        internal static ListingCounts Observe(GuestRootRecord record, string relative)
        {
            record.Validate(); FixtureProtocol.Relative(relative);
            if (!record.PublicListing) throw new BrokerError("guest_fixture_listing_refused");
            return Enumerate(record, relative, null);
        }
        internal static int ObserveApproved(GuestRootRecord record, string relative, string digest)
        {
            record.Validate(); FixtureProtocol.Relative(relative);
            if (record.ApprovedListing == null) throw new BrokerError("guest_fixture_listing_refused");
            ApprovedListing plan = record.ApprovedListing; plan.Demand(relative);
            if (!FixtureProtocol.Hex(digest, 64) || plan.Digest() != digest) throw new BrokerError("guest_fixture_listing_refused");
            List<PublicFixtureEntry> entries = plan.Ordered(); int mask = 0;
            Enumerate(record, relative, delegate(string name, bool directory)
            {
                int index = entries.FindIndex(delegate(PublicFixtureEntry entry) { return entry.Name == name && (entry.Kind == "directory") == directory; });
                if (index < 0) throw new BrokerError("guest_fixture_listing_refused");
                mask |= 1 << index;
            });
            return ApprovedListing.ExitBase + mask; // Only after native end-of-enumeration, never a partial bitmap.
        }
        private static ListingCounts Enumerate(GuestRootRecord record, string relative, Action<string, bool> accepted)
        {
            using (PinnedDirectory root = PinnedDirectory.Open(record.RootPath))
            {
                if (root.Identity != record.RootIdentity) throw new BrokerError("guest_fixture_root_changed");
                string path = Path.Combine(record.RootPath, relative);
                using (PinnedDirectory directory = PinnedDirectory.Open(path))
                {
                    // Fresh directory handle, restart on first batch, advance on
                    // the same retained handle thereafter. Never FindFirst(path).
                    IntPtr buffer = Marshal.AllocHGlobal(BufferBytes);
                    var pins = new List<SafeFileHandle>(); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    int files = 0, directories = 0;
                    try
                    {
                        for (int batch = 0; batch < MaximumBatches; batch++)
                        {
                            for (int i = 0; i < BufferBytes; i++) Marshal.WriteByte(buffer, i, 0);
                            if (!Native.GetFileInformationByHandleEx(directory.Handle, batch == 0 ? 11 : 10, buffer, BufferBytes))
                            {
                                int error = Marshal.GetLastWin32Error();
                                if (error == 18) return new ListingCounts(files, directories); // ERROR_NO_MORE_FILES only.
                                throw new BrokerError("guest_fixture_listing_refused");
                            }
                            ParseBatch(buffer, BufferBytes, delegate(string name, bool isDirectory)
                            {
                                if (!names.Add(name) || names.Count > ListingCounts.Maximum) throw new BrokerError("guest_fixture_listing_refused");
                                // No-follow open of this already pinned parent's
                                // single validated child; retain every child until
                                // the whole bounded observation is complete. No data
                                // is read, no ID grants later access or deletion.
                                string child = Path.Combine(path, name);
                                var security = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)) };
                                SafeFileHandle pin = Native.CreateFileW(child, 0x81, 1, ref security, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
                                if (pin.IsInvalid) { pin.Dispose(); throw new BrokerError("guest_fixture_listing_refused"); }
                                pins.Add(pin); HostPaths.CheckHandle(pin, child, isDirectory);
                                Native.FileInformation information;
                                if (!Native.GetFileInformationByHandle(pin, out information) || information.Attributes == 0 || (information.Attributes & ~AllowedAttributes) != 0) throw new BrokerError("guest_fixture_listing_refused");
                                if (accepted != null) accepted(name, isDirectory);
                                if (isDirectory) directories++; else files++;
                            });
                        }
                        throw new BrokerError("guest_fixture_listing_refused"); // No truncated/partial count success.
                    }
                    finally
                    {
                        for (int i = pins.Count - 1; i >= 0; i--) pins[i].Dispose();
                        for (int i = 0; i < BufferBytes; i++) Marshal.WriteByte(buffer, i, 0);
                        Marshal.FreeHGlobal(buffer);
                    }
                }
            }
        }
    }
}
