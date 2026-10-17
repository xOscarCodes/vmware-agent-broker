using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace GuestBroker
{
    // Never implement ToString, serialization, logging, or a managed-string getter here.
    internal sealed class SecretBuffer : IDisposable
    {
        internal IntPtr Pointer { get; private set; }
        internal int Size { get; private set; }
        internal SecretBuffer(int bytes)
        {
            if (bytes < 1 || bytes > 65536) throw new BrokerError("credential_size_rejected");
            Size = bytes;
            Pointer = Marshal.AllocHGlobal(bytes);
            Wipe(Pointer, Size);
        }

        // Minimal unsafe boundary: volatile byte stores cannot be optimized away.
        // Caller owns a live allocation of at least size bytes, including on cleanup paths.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static unsafe void Wipe(IntPtr pointer, int size)
        {
            byte* p = (byte*)pointer.ToPointer();
            for (int i = 0; i < size; i++) Volatile.Write(ref p[i], (byte)0);
        }

        internal int WideLength()
        {
            for (int i = 0; i < Size / 2; i++) if (Marshal.ReadInt16(Pointer, i * 2) == 0) return i;
            throw new BrokerError("credential_size_rejected");
        }

        internal SecretBuffer Utf8()
        {
            int chars = WideLength();
            if (chars == 0) throw new BrokerError("empty_credential_rejected");
            int bytes = Native.WideCharToMultiByte(65001, 0x80, Pointer, chars, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
            if (bytes < 1) throw new BrokerError("credential_encoding_rejected");
            var result = new SecretBuffer(bytes + 1);
            if (Native.WideCharToMultiByte(65001, 0x80, Pointer, chars, result.Pointer, bytes, IntPtr.Zero, IntPtr.Zero) != bytes)
            {
                result.Dispose();
                throw new BrokerError("credential_encoding_rejected");
            }
            return result;
        }

        internal void CopyFrom(IntPtr source, int bytes, int offset)
        {
            if (bytes < 0 || offset < 0 || offset > Size || bytes > Size - offset) throw new BrokerError("credential_size_rejected");
            for (int i = 0; i < bytes; i++) Marshal.WriteByte(Pointer, offset + i, Marshal.ReadByte(source, i));
        }

        public void Dispose()
        {
            if (Pointer == IntPtr.Zero) return;
            Wipe(Pointer, Size);
            Marshal.FreeHGlobal(Pointer);
            Pointer = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }
        ~SecretBuffer() { Dispose(); }
    }

    internal sealed class GuestCredential : IDisposable
    {
        internal SecretBuffer User, Password;
        internal readonly string Binding;
        internal GuestCredential(Target target, SecretBuffer user, SecretBuffer password) { Binding = target.Binding; User = user; Password = password; }

        internal static GuestCredential Prompt(Target target, bool persist)
        {
            return PromptCore(target, persist, CallPrompt);
        }
        internal delegate uint PromptCall(ref Native.CredUi ui, ref uint package, ref IntPtr blob, ref uint bytes, ref int save, uint flags);
        private static uint CallPrompt(ref Native.CredUi ui, ref uint package, ref IntPtr blob, ref uint bytes, ref int save, uint flags)
        {
            return Native.CredUIPromptForWindowsCredentialsW(ref ui, 0, ref package, IntPtr.Zero, 0, ref blob, ref bytes, ref save, flags);
        }
        // Tests substitute ONLY the native prompt call, never invoke the UI or vault.
        internal static GuestCredential PromptCore(Target target, bool persist, PromptCall prompt)
        {
            var ui = new Native.CredUi();
            ui.Size = (uint)Marshal.SizeOf(typeof(Native.CredUi));
            ui.Caption = "VMware Guest Broker - " + target.Name;
            ui.Message = "Guest credentials for " + target.Name + " at " + target.Vmx + " (UUID " + target.Uuid + "). Use the guest account, NOT your host account. " +
                (persist ? "Store in Windows Credential Manager ONLY if you also tick Save. Grants broker read-only authentication; timezone still requires consent each time." : "One operation only; credentials will NOT be saved.");
            uint package = 0, blobSize = 0;
            int save = 0;
            IntPtr blob = IntPtr.Zero;
            Diagnostics.At(Stage.CredentialPrompt);
            // Explicit initialized ref storage also gives deterministic null/zero
            // inputs if the native API leaves its outputs untouched on cancellation.
            uint error = prompt(ref ui, ref package, ref blob, ref blobSize, ref save, persist ? 3u : 1u);
            try
            {
                Diagnostics.At(Stage.CredentialPromptReturned);
                if (error != 0) throw new BrokerError(PromptError(error));
                if (persist && save == 0) throw new BrokerError("storage_not_approved");
                if (blob == IntPtr.Zero || blobSize == 0 || blobSize > 65536) throw new BrokerError("credential_size_rejected");
                Diagnostics.At(Stage.CredentialUnpack);
                using (var user = new SecretBuffer(1026))
                using (var domain = new SecretBuffer(514))
                {
                    var password = new SecretBuffer(2562);
                    SecretBuffer joined = null;
                    try
                    {
                        uint u = 513, d = 257, p = 1281;
                        if (!Native.CredUnPackAuthenticationBufferW(0, blob, blobSize, user.Pointer, ref u, domain.Pointer, ref d, password.Pointer, ref p))
                            throw new BrokerError("credential_unpack_failed");
                        int dl = domain.WideLength(), ul = user.WideLength();
                        if (ul == 0 || password.WideLength() == 0) throw new BrokerError("empty_credential_rejected");
                        joined = new SecretBuffer((dl + ul + 2) * 2);
                        int offset = 0;
                        if (dl != 0)
                        {
                            joined.CopyFrom(domain.Pointer, dl * 2, 0);
                            Marshal.WriteInt16(joined.Pointer, dl * 2, (short)'\\');
                            offset = (dl + 1) * 2;
                        }
                        joined.CopyFrom(user.Pointer, ul * 2, offset);
                        return new GuestCredential(target, joined, password);
                    }
                    catch { if (joined != null) joined.Dispose(); password.Dispose(); throw; }
                }
            }
            finally
            {
                if (blob != IntPtr.Zero)
                {
                    SecretBuffer.Wipe(blob, checked((int)blobSize));
                    Marshal.FreeCoTaskMem(blob);
                }
            }
        }
        internal static string PromptError(uint code)
        {
            if (code == 1223) return "user_cancelled";
            if (code == 87) return "credential_prompt_invalid_parameter";
            if (code == 1004) return "credential_prompt_invalid_flags";
            if (code == 1312) return "credential_prompt_no_logon_session";
            return "credential_prompt_failed";
        }

        internal void Save(Target selected)
        {
            if (Binding != selected.Binding) throw new BrokerError("credential_target_mismatch");
            int bytes = Password.WideLength() * 2;
            if (bytes > 2560) throw new BrokerError("credential_size_rejected");
            IntPtr target = Marshal.StringToHGlobalUni(selected.CredentialKey);
            IntPtr comment = Marshal.StringToHGlobalUni(selected.Binding);
            try
            {
                var cred = new Native.Credential();
                cred.Type = 1; // CRED_TYPE_GENERIC; never domain/host credentials.
                cred.Target = target;
                cred.Comment = comment;
                cred.User = User.Pointer;
                cred.Blob = Password.Pointer;
                cred.BlobSize = (uint)bytes;
                cred.Persist = 2; // Same Windows user on this machine; not enterprise roaming.
                if (!Native.CredWriteW(ref cred, 0)) throw new BrokerError("credential_save_failed");
            }
            finally { Marshal.FreeHGlobal(target); Marshal.FreeHGlobal(comment); }
        }

        internal static void ValidateBinding(Target selected, Native.Credential cred)
        {
            if (cred.Type != 1 || !MetadataEquals(cred.Target, selected.CredentialKey) || !MetadataEquals(cred.Comment, selected.Binding))
                throw new BrokerError("credential_target_mismatch");
        }

        private static bool MetadataEquals(IntPtr pointer, string expected)
        {
            if (pointer == IntPtr.Zero) return false;
            for (int i = 0; i < expected.Length; i++) if ((ushort)Marshal.ReadInt16(pointer, i * 2) != expected[i]) return false;
            return Marshal.ReadInt16(pointer, expected.Length * 2) == 0;
        }

        internal static GuestCredential Read(Target selected)
        {
            Diagnostics.At(Stage.CredentialRead);
            IntPtr ptr;
            if (!Native.CredReadW(selected.CredentialKey, 1, 0, out ptr)) throw new BrokerError("credential_unavailable");
            Native.Credential cred = new Native.Credential();
            try
            {
                cred = (Native.Credential)Marshal.PtrToStructure(ptr, typeof(Native.Credential));
                ValidateBinding(selected, cred);
                if (cred.Type != 1 || cred.BlobSize < 2 || cred.BlobSize > 2560 || cred.BlobSize % 2 != 0 || cred.Blob == IntPtr.Zero || cred.User == IntPtr.Zero)
                    throw new BrokerError("credential_format_rejected");
                int userChars = 0;
                while (userChars <= 770 && Marshal.ReadInt16(cred.User, userChars * 2) != 0) userChars++;
                if (userChars == 0 || userChars > 770) throw new BrokerError("credential_format_rejected");
                var user = new SecretBuffer((userChars + 1) * 2);
                SecretBuffer password = null;
                try
                {
                    password = new SecretBuffer((int)cred.BlobSize + 2);
                    user.CopyFrom(cred.User, userChars * 2, 0);
                    password.CopyFrom(cred.Blob, (int)cred.BlobSize, 0);
                    if (password.WideLength() * 2 != cred.BlobSize) throw new BrokerError("credential_format_rejected");
                    return new GuestCredential(selected, user, password);
                }
                catch { user.Dispose(); if (password != null) password.Dispose(); throw; }
            }
            finally
            {
                // Wipe the API-owned secret before CredFree, even if format validation failed.
                if (cred.Blob != IntPtr.Zero) SecretBuffer.Wipe(cred.Blob, checked((int)cred.BlobSize));
                Native.CredFree(ptr);
            }
        }

        internal static void Revoke(Target selected)
        {
            if (!Native.CredDeleteW(selected.CredentialKey, 1, 0) && Marshal.GetLastWin32Error() != 1168)
                throw new BrokerError("credential_delete_failed");
        }

        public void Dispose() { User.Dispose(); Password.Dispose(); }
    }
}
