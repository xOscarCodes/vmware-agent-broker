using System;
using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace GuestBroker
{
    // The only platform boundary. All secret arguments are pointers, never strings.
    internal static partial class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct FileInformation
        {
            internal uint Attributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct FileIdInformation
        {
            internal ulong Volume, IdLow, IdHigh;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CredUi
        {
            internal uint Size;
            internal IntPtr Parent;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Message;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Caption;
            internal IntPtr Banner;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Credential
        {
            internal uint Flags, Type;
            internal IntPtr Target, Comment;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            internal uint BlobSize;
            internal IntPtr Blob;
            internal uint Persist, AttributeCount;
            internal IntPtr Attributes, Alias, User;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TrustFile
        {
            internal uint Size;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Path;
            internal IntPtr File, KnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TrustData
        {
            internal uint Size;
            internal IntPtr PolicyCallback, SipClient;
            internal uint Ui, Revocation, UnionChoice;
            internal IntPtr File;
            internal uint StateAction;
            internal IntPtr State, Url;
            internal uint Flags, UiContext;
            internal IntPtr SignatureSettings;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetDefaultDllDirectories(uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetModuleFileNameW(IntPtr module, System.Text.StringBuilder path, int size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle file, System.Text.StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, out FileInformation information);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(Microsoft.Win32.SafeHandles.SafeFileHandle file, int informationClass, out FileIdInformation information, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int WideCharToMultiByte(uint codePage, uint flags, IntPtr input, int chars, IntPtr output, int bytes, IntPtr defaultChar, IntPtr usedDefaultChar);
        [DllImport("kernel32.dll")]
        internal static extern uint SetErrorMode(uint mode);
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal static extern uint CredUIPromptForWindowsCredentialsW(ref CredUi ui, uint error, ref uint package, IntPtr input, uint inputSize, ref IntPtr output, ref uint outputSize, ref int save, uint flags);
        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredUnPackAuthenticationBufferW(uint flags, IntPtr auth, uint authSize, IntPtr user, ref uint userChars, IntPtr domain, ref uint domainChars, IntPtr password, ref uint passwordChars);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredWriteW(ref Credential credential, uint flags);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredDeleteW(string target, uint type, uint flags);
        [DllImport("advapi32.dll")]
        internal static extern void CredFree(IntPtr credential);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "MessageBoxW", ExactSpelling = true)]
        private static extern int NativeMessageBoxW(IntPtr parent, string text, string caption, uint flags);
        internal static int MessageBoxW(IntPtr parent, string text, string caption, uint flags) { return NativeMessageBoxW(parent, UiText.Lines(text), caption, flags); }
    }
}
