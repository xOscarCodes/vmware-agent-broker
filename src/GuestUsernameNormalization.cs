using System;
using System.Runtime.InteropServices;

namespace GuestBroker
{
    // In-process native adapter only, never an IPC/helper/CLI credential carrier.
    internal interface IGuestUsernameLogin
    {
        void Authenticate(SecretBuffer user, int options);
        string ComputerName();
        void Logout();
        void Revalidate();
        void Retain(SecretBuffer user);
    }
    internal static class GuestUsernameNormalization
    {
        // Fixed shape/progress labels ONLY. Never store a name or credential here.
        internal static string Form;
        internal static bool SafeForm(string form)
        {
            return form == null || form == "dot_local_preflight" || form == "dot_local_guest_sam" ||
                form == "unqualified_unchanged" || form == "sam_qualified_unchanged" || form == "upn_unchanged";
        }
        private static char At(SecretBuffer user, int index) { return unchecked((char)(ushort)Marshal.ReadInt16(user.Pointer, index * 2)); }
        internal static bool DotLocal(SecretBuffer user)
        {
            int length = user.WideLength();
            return length >= 2 && At(user, 0) == '.' && At(user, 1) == '\\';
        }
        private static int ValidateLocal(SecretBuffer user)
        {
            // Preserve the explicit LOCAL principal; never strip a real domain or
            // guess from a host account/computer, registry alias, UPN or SID.
            int length = user.WideLength();
            if (!DotLocal(user) || length <= 2) throw new BrokerError("credential_format_rejected");
            for (int i = 2; i < length; i++)
            {
                char c = At(user, i);
                if (Char.IsControl(c) || c == '\\' || c == '/' || c == '@') throw new BrokerError("credential_format_rejected");
            }
            return length;
        }
        internal static SecretBuffer QualifyLocal(SecretBuffer user, string computer)
        {
            int length = ValidateLocal(user);
            Policy.SafeHostname(computer);
            var result = new SecretBuffer(checked((computer.Length + length) * 2));
            try
            {
                for (int i = 0; i < computer.Length; i++) Marshal.WriteInt16(result.Pointer, i * 2, (short)computer[i]);
                Marshal.WriteInt16(result.Pointer, computer.Length * 2, (short)'\\');
                result.CopyFrom(IntPtr.Add(user.Pointer, 4), (length - 2) * 2, (computer.Length + 1) * 2);
                return result;
            }
            catch { result.Dispose(); throw; }
        }
        internal static void Login(SecretBuffer wideUser, SecretBuffer utf8User, int options, IGuestUsernameLogin native)
        {
            if (options != 0 && options != NativePlans.RequireInteractiveEnvironment) throw new BrokerError("invalid_request");
            if (options != NativePlans.RequireInteractiveEnvironment) { native.Authenticate(utf8User, options); return; }
            if (!DotLocal(wideUser))
            {
                Form = "unqualified_unchanged";
                for (int i = 0; i < wideUser.WideLength(); i++)
                {
                    char c = At(wideUser, i);
                    if (c == '\\') { Form = "sam_qualified_unchanged"; break; }
                    if (c == '@') Form = "upn_unchanged";
                }
                native.Authenticate(utf8User, NativePlans.RequireInteractiveEnvironment); return;
            }
            // Exactly one original authentication, one fixed bounded guest-name
            // read, checked logout, then one canonical interactive authentication.
            // This is BEFORE login8, not a fallback after a failed interactive call.
            // The native adapter reuses the SAME password pointer for both calls.
            ValidateLocal(wideUser);
            Form = "dot_local_preflight";
            native.Authenticate(utf8User, 0);
            SecretBuffer qualified = null;
            try { qualified = QualifyLocal(wideUser, native.ComputerName()); }
            finally { try { native.Logout(); } catch { if (qualified != null) qualified.Dispose(); throw; } }
            using (qualified)
            {
                native.Revalidate();
                SecretBuffer utf8 = qualified.Utf8();
                try { native.Retain(utf8); } catch { utf8.Dispose(); throw; }
                // Retained through VM/host teardown even when native login8 fails.
                Form = "dot_local_guest_sam";
                native.Authenticate(utf8, NativePlans.RequireInteractiveEnvironment);
            }
        }
    }
}
