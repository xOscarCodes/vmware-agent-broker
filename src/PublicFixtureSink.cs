using System;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace GuestBroker
{
    internal static partial class Native
    {
        [DllImport("user32.dll")] internal static extern IntPtr GetForegroundWindow();
    }
    internal static class PublicFixtureSink
    {
        internal const string Sample = "BROKER-PUBLIC-123";
        internal static void SampleName(string name) { if (name != "PUBLIC_ALNUM") throw new BrokerError("guest_fixture_process_refused"); }
        internal static uint Accept(uint operation, bool focused, Action<string> append)
        {
            if (operation != 4) throw new BrokerError("guest_fixture_process_refused");
            if (!focused) return 4;
            append(Sample); return 2;
        }
        internal static int Run(string input, string output)
        {
            using (var commands = new AnonymousPipeClientStream(PipeDirection.In, input))
            using (var replies = new AnonymousPipeClientStream(PipeDirection.Out, output))
            using (var form = new Form { Text = "BROKER PUBLIC FIXTURE ONLY - no private input", Width = 600, Height = 260, StartPosition = FormStartPosition.CenterScreen })
            using (var text = new TextBox { ReadOnly = true, ShortcutsEnabled = false, ContextMenu = new ContextMenu(), Multiline = true, Dock = DockStyle.Fill })
            using (var timer = new System.Windows.Forms.Timer { Interval = 25 })
            {
                form.Controls.Add(text); var lifetime = Stopwatch.StartNew();
                timer.Tick += delegate
                {
                    try
                    {
                        if (lifetime.ElapsedMilliseconds > 35000) { form.Close(); return; }
                        uint available;
                        if (!Native.PeekNamedPipe(commands.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) { form.Close(); return; }
                        if (available == 0) return;
                        uint request = GuestProcessSupervisor.ReadFrame(commands, 100);
                        bool focused = form.ContainsFocus && text.Focused && Native.GetForegroundWindow() == form.Handle;
                        uint status = Accept(request, focused, delegate(string sample) { if (text.TextLength + sample.Length > 1024) throw new BrokerError("guest_fixture_process_refused"); text.AppendText(sample); });
                        GuestProcessSupervisor.WriteFrame(replies, status);
                    }
                    catch (Exception) { form.Close(); } // No clipboard, text readback, global key injection or foreign HWND target.
                };
                timer.Start(); Application.Run(form); return 0;
            }
        }
#if BROKER_TESTS
        internal static int RunForTest(string input, string output)
        {
            using (var commands = new AnonymousPipeClientStream(PipeDirection.In, input))
            using (var replies = new AnonymousPipeClientStream(PipeDirection.Out, output))
            {
                var lifetime = Stopwatch.StartNew();
                while (lifetime.ElapsedMilliseconds < 35000)
                {
                    uint available; if (!Native.PeekNamedPipe(commands.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) return 0;
                    if (available != 0) GuestProcessSupervisor.WriteFrame(replies, Accept(GuestProcessSupervisor.ReadFrame(commands, 100), true, delegate(string sample) { if (sample != Sample) throw new BrokerError("guest_fixture_process_refused"); }));
                    Thread.Sleep(10);
                }
                return 0;
            }
        }
#endif
    }
}
