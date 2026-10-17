using System;

namespace GuestBroker
{
    internal static class ToolsReadiness
    {
        internal const int WaitSeconds = 30;
        internal const int MountOnlyReturnImmediately = 2; // MOUNT0 | RETURN_IMMEDIATELY2, never AUTO_UPGRADE1.
        internal static int Observe(int power, Func<int> readState, Action<int> wait, out bool waited)
        {
            int state = readState(); waited = false;
            if (state != 2 && (power & 0x0008) != 0 && (power & 0x0200) == 0)
            {
                Diagnostics.At(Stage.ToolsWait);
                try { wait(WaitSeconds); } catch { Diagnostics.Fault(); throw; }
                waited = true;
                state = readState(); // Actual SAME native handle property, NOT an assumed healthy value.
            }
            return state;
        }
    }
}
