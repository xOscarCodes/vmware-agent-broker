namespace GuestBroker
{
    internal static class UiText
    {
        // Rendering boundary only. Never apply this to code, paths, native input,
        // serialized policy values or command arguments.
        internal static string Lines(string text)
        {
            return text == null ? null : text.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n");
        }
    }
}
