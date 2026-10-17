using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace GuestBroker
{
    internal static partial class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint instances, uint output, uint input, uint timeout, ref SecurityAttributes security);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool inJob);
    }
    internal static class GuestProcessSupervisor
    {
        internal const int LifetimeMilliseconds = 30000;
        private const uint Magic = 0x58464742;
        internal static void Slot(string slot) { if (slot != "slot1" && slot != "slot2" && slot != "slot3" && slot != "slot4") throw new BrokerError("guest_fixture_process_refused"); }
        internal static bool Current(GuestRootStore store, GuestRootRecord root)
        {
            try { GuestRootRecord now = store.Read(root.TargetBinding, root.Alias); return now.OwnedProcesses && now.EnrollmentId == root.EnrollmentId && now.ImageSha256 == root.ImageSha256 && now.RootIdentity == root.RootIdentity && now.RootPath == root.RootPath; }
            catch (Exception) { return false; }
        }
        internal static void Start(GuestRootStore store, GuestRootRecord root, string slot)
        { StartCore(store, root, slot, null, LifetimeMilliseconds); }
#if BROKER_TESTS
        internal static void StartForTest(GuestRootStore store, GuestRootRecord root, string slot, string testStore, int lifetime)
        { StartCore(store, root, slot, testStore, lifetime); }
#endif
        private static void StartCore(GuestRootStore store, GuestRootRecord root, string slot, string testStore, int lifetime)
        {
            root.Validate(); Slot(slot); if (lifetime < 1000 || lifetime > LifetimeMilliseconds || !Current(store, root)) throw new BrokerError("guest_fixture_process_refused");
            using (store.MutationLock())
            using (var rootPin = PinnedDirectory.Open(root.RootPath))
            using (var image = FixtureImagePin.Open(root.ImageSha256))
            {
                if (rootPin.Identity != root.RootIdentity || !Current(store, root) || store.ProcessExists(root, slot)) throw new BrokerError("guest_fixture_process_refused");
                var record = new FixtureProcessRecord { Binding = root.TargetBinding, RootAlias = root.Alias, Enrollment = root.EnrollmentId, Image = root.ImageSha256, Slot = slot, Instance = Guid.NewGuid().ToString("N").ToUpperInvariant(), Expires = DateTime.UtcNow.AddMilliseconds(lifetime).Ticks };
                string[] args = { "supervise-fixture", root.TargetBinding, root.Alias, root.EnrollmentId, root.ImageSha256, slot, record.Instance };
#if BROKER_TESTS
                if (testStore != null) args = new[] { "--supervise-fixture-test", testStore, lifetime.ToString(System.Globalization.CultureInfo.InvariantCulture), root.TargetBinding, root.Alias, root.EnrollmentId, root.ImageSha256, slot, record.Instance };
#endif
                using (OwnedFixtureProcess supervisor = OwnedFixtureProcess.Start(image, args, false))
                {
                    record.Supervisor = supervisor.Id; record.Created = supervisor.Created; store.WriteProcess(root, record); supervisor.Resume();
                    var clock = Stopwatch.StartNew(); bool ready = false;
#if BROKER_TESTS
                    int lastError = 0;
                    int lastPhase = 0;
#endif
                    while (clock.ElapsedMilliseconds < 5000 && !supervisor.Exited)
                    {
                        try { if (Exchange(root, record, 1, image.Path, 150) == 1) { ready = true; break; } }
                        catch (Exception error)
                        {
#if BROKER_TESTS
                            lastError = error.HResult & 0xffff;
                            if (error.Data["FixtureSafePhase"] is int) lastPhase = (int)error.Data["FixtureSafePhase"];
#endif
                            GC.KeepAlive(error);
                        }
                        Thread.Sleep(20);
                    }
                    if (!ready || !Current(store, root))
                    {
#if BROKER_TESTS
                        Console.WriteLine("SYNTHETIC fixture readiness failure: supervisor status=0x" + supervisor.SafeExitStatus.ToString("X8") + "; managed-code=" + lastError + "; safe-phase=" + lastPhase);
#endif
                        throw new BrokerError("guest_fixture_mutation_uncertain");
                    }
                    supervisor.DetachSupervisor(); // Only this fixed supervisor may outlive the launcher, with a hard expiry.
                }
            }
        }
        internal static void Stop(GuestRootStore store, GuestRootRecord root, string slot)
        { Control(store, root, slot, 2); }
        internal static void Type(GuestRootStore store, GuestRootRecord root, string slot, string sample)
        { PublicFixtureSink.SampleName(sample); if (!root.OwnedSink) throw new BrokerError("guest_fixture_process_refused"); Control(store, root, slot, 4); }
        private static void Control(GuestRootStore store, GuestRootRecord root, string slot, uint operation)
        {
            root.Validate(); Slot(slot); if (!Current(store, root)) throw new BrokerError("guest_fixture_process_refused");
            FixtureProcessRecord record;
            try { record = store.ReadProcess(root, slot); } catch (Exception) { throw new BrokerError("guest_fixture_process_refused"); }
            if (DateTime.UtcNow.Ticks >= record.Expires) throw new BrokerError("guest_fixture_process_refused");
            using (var image = FixtureImagePin.Open(root.ImageSha256))
                if (Exchange(root, record, operation, image.Path, 1500) != (operation == 2 ? 0u : 2u)) throw new BrokerError("guest_fixture_process_refused");
        }
        internal static int Run(GuestRootStore store, GuestRootRecord root, string slot, string instance, int lifetime, string ownerJob)
        {
            long value; bool inJob;
            if (!Int64.TryParse(ownerJob, out value) || value <= 0 || !Native.IsProcessInJob(new IntPtr(-1), new IntPtr(value), out inJob) || !inJob) return FixtureProtocol.MutationRefused;
            IntPtr ownJob = new IntPtr(value); FixtureProcessRecord record = null;
            using (var watchdog = new Timer(delegate { Native.TerminateProcess(new IntPtr(-1), 124); }, null, Math.Max(1000, Math.Min(lifetime, LifetimeMilliseconds)) + 5000, Timeout.Infinite))
            try
            {
                Slot(slot); if (!FixtureProtocol.Hex(instance, 32) || lifetime < 1000 || lifetime > LifetimeMilliseconds || !Current(store, root)) return FixtureProtocol.MutationRefused;
                var startup = Stopwatch.StartNew();
                while (record == null && startup.ElapsedMilliseconds < 2000)
                { try { record = store.ReadProcess(root, slot); } catch (Exception) { Thread.Sleep(20); } }
                using (Process self = Process.GetCurrentProcess()) if (record == null || record.Instance != instance || record.Supervisor != (uint)self.Id) return FixtureProtocol.MutationRefused;
                int budget = (int)Math.Min(lifetime, Math.Max(0, (record.Expires - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond));
                if (budget < 1) return 0;
                using (var rootPin = PinnedDirectory.Open(root.RootPath))
                using (var image = FixtureImagePin.Open(root.ImageSha256))
                using (var server = Server(record.PipeName(root)))
                using (var commands = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
                using (var replies = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
                using (OwnedFixtureProcess child = OwnedFixtureProcess.Start(image, new[] { "fixture-sink", commands.GetClientHandleAsString(), replies.GetClientHandleAsString() }, true, commands, replies))
                {
                    if (rootPin.Identity != root.RootIdentity) return FixtureProtocol.RootChanged;
                    commands.DisposeLocalCopyOfClientHandle(); replies.DisposeLocalCopyOfClientHandle(); child.Resume(); var clock = Stopwatch.StartNew(); bool done = false;
                    while (!done && clock.ElapsedMilliseconds < budget && Current(store, root) && !child.Exited)
                    {
                        IAsyncResult wait = server.BeginWaitForConnection(null, null);
                        while (!wait.AsyncWaitHandle.WaitOne(50))
                            if (clock.ElapsedMilliseconds >= budget || !Current(store, root) || child.Exited) return 0;
                        server.EndWaitForConnection(wait);
                        try
                        {
                            uint operation = ReadFrame(server, 1000);
                            if (!Current(store, root) || clock.ElapsedMilliseconds >= budget || !child.SafeIdentity()) throw new BrokerError("guest_fixture_process_refused");
                            if (operation == 2) { child.Stop(); WriteFrame(server, 0); done = true; }
                            else if (operation == 1 && !child.Exited) WriteFrame(server, 1);
                            else if (operation == 4 && store.Read(root.TargetBinding, root.Alias).OwnedSink)
                            {
                                WriteFrame(commands, 4); uint typed = ReadFrame(replies, 1000);
                                if (typed != 2 && typed != 4) throw new BrokerError("guest_fixture_process_refused"); WriteFrame(server, typed);
                            }
                            else throw new BrokerError("guest_fixture_process_refused");
                            // DisconnectNamedPipe discards unread output. Require a
                            // fixed bounded ACK instead of an unbounded pipe drain.
                            if (ReadFrame(server, 1000) != 3) throw new BrokerError("guest_fixture_process_refused");
                        }
                        catch (Exception) { /* Fixed protocol, no raw pipe/exception data. Owner's child remains TTL-bound. */ }
                        finally { if (server.IsConnected) server.Disconnect(); }
                    }
                }
                return 0;
            }
            finally
            {
                try { if (record != null) using (store.MutationLock()) store.RemoveProcess(root, record); } catch (Exception) { /* Stale marker blocks restart; never auto-adopt it. */ }
                var limits = new Native.JobLimits(); Native.SetInformationJobObject(ownJob, 9, ref limits, (uint)Marshal.SizeOf(typeof(Native.JobLimits))); Native.CloseHandle(ownJob);
            }
        }
        private static NamedPipeServerStream Server(string name)
        {
            var acl = new PipeSecurity();
            using (var identity = WindowsIdentity.GetCurrent()) { acl.SetOwner(identity.User); acl.SetAccessRuleProtection(true, false); acl.AddAccessRule(new PipeAccessRule(identity.User, PipeAccessRights.FullControl, AccessControlType.Allow)); }
            byte[] descriptor = acl.GetSecurityDescriptorBinaryForm(); GCHandle pin = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                var attributes = new Native.SecurityAttributes { Size = Marshal.SizeOf(typeof(Native.SecurityAttributes)), Descriptor = pin.AddrOfPinnedObject() };
                SafePipeHandle handle = Native.CreateNamedPipeW(@"\\.\pipe\" + name, 3 | 0x80000 | 0x40000000, 8, 1, 64, 64, 1000, ref attributes); // first instance, OVERLAPPED, REJECT_REMOTE_CLIENTS.
                if (handle.IsInvalid) { handle.Dispose(); throw new BrokerError("guest_fixture_process_refused"); }
                return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
            }
            finally { pin.Free(); }
        }
        private static uint Exchange(GuestRootRecord root, FixtureProcessRecord record, uint operation, string image, int timeout)
        {
            // OpenProcess is QUERY_LIMITED_INFORMATION | SYNCHRONIZE ONLY. Never
            // acquire terminate authority from a PID or reopen the fixture by PID.
            IntPtr view = Native.OpenProcess(0x1000 | 0x100000, false, record.Supervisor);
            bool dispatchedMutation = false;
            try
            {
                if (view == IntPtr.Zero) throw SafeRefusal(1);
                if (Native.WaitForSingleObject(view, 0) != 258) throw SafeRefusal(2);
                if (!OwnedFixtureProcess.ReadOnlyIdentity(view, record.Created, image)) throw SafeRefusal(3);
                using (var client = new NamedPipeClientStream(".", record.PipeName(root), PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous))
                {
                    client.Connect(timeout); uint server;
                    if (!Native.GetNamedPipeServerProcessId(client.SafePipeHandle, out server) || server != record.Supervisor || Native.WaitForSingleObject(view, 0) != 258) throw SafeRefusal(5);
                    dispatchedMutation = operation == 2 || operation == 4; WriteFrame(client, operation);
                    try { uint reply = ReadFrame(client, timeout); if (reply > 4 || reply == 3) throw SafeRefusal(6); WriteFrame(client, 3); return reply; } catch (Exception) { throw SafeRefusal(6); }
                }
            }
            catch (Exception error) { if (dispatchedMutation) throw new BrokerError("guest_fixture_mutation_uncertain"); if (error is BrokerError) throw; throw SafeRefusal(4); }
            finally { if (view != IntPtr.Zero) Native.CloseHandle(view); }
        }
        private static BrokerError SafeRefusal(int phase) { var error = new BrokerError("guest_fixture_process_refused"); error.Data["FixtureSafePhase"] = phase; return error; }
        internal static void WriteFrame(PipeStream pipe, uint value)
        { byte[] bytes = new byte[8]; Array.Copy(BitConverter.GetBytes(Magic), bytes, 4); Array.Copy(BitConverter.GetBytes(value), 0, bytes, 4, 4); pipe.Write(bytes, 0, bytes.Length); }
        internal static uint ReadFrame(PipeStream pipe, int timeout)
        {
            var clock = Stopwatch.StartNew(); uint available;
            while (true)
            {
                if (!Native.PeekNamedPipe(pipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) throw new BrokerError("guest_fixture_process_refused");
                if (available >= 8) break;
                if (clock.ElapsedMilliseconds > timeout) throw new BrokerError("guest_fixture_process_refused"); Thread.Sleep(10);
            }
            if (available != 8) throw new BrokerError("guest_fixture_process_refused");
            var bytes = new byte[8]; int read = 0; while (read < bytes.Length) { int n = pipe.Read(bytes, read, bytes.Length - read); if (n == 0) throw new BrokerError("guest_fixture_process_refused"); read += n; }
            if (BitConverter.ToUInt32(bytes, 0) != Magic) throw new BrokerError("guest_fixture_process_refused"); return BitConverter.ToUInt32(bytes, 4);
        }
    }
}
