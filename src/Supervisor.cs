using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace GuestBroker
{
    internal sealed class SupervisedResult
    {
        internal ResultData Result;
        internal int ExitCode;
    }

    internal static class Supervisor
    {
        internal static SupervisedResult Run(Request request)
        {
            int budget = request.Vmrun != null && (request.Vmrun.Entry.Name == "clone" || request.Vmrun.Entry.Name == "deleteVM") ? 905000 : request.Vmrun != null && request.Vmrun.Entry.Name == "downloadPhotonVM" ? 605000 : 50000;
            return RunCore(typeof(Program).Assembly.Location, request.WorkerArguments(), request.Diagnostic, budget);
        }

        // Used with this utility's own executable only. Tests call their own test
        // executable with fixed synthetic tokens; this is not an external CLI API.
        internal static SupervisedResult RunCore(string executable, string[] args, bool diagnostic, int deadlineMilliseconds)
        {
            Stage stage = Stage.Starting;
            ResultData result = null;
            int frames = 0;
            bool resolved = false, cancelled = false, timedOut = false, badProtocol = false;
            int cancelRequested = 0;
            var line = new StringBuilder();
            var elapsed = Stopwatch.StartNew();
            ConsoleCancelEventHandler cancel = delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; Interlocked.Exchange(ref cancelRequested, 1); };
            Console.CancelKeyPress += cancel;
            try
            {
                using (var pipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
                using (WorkerProcess worker = WorkerProcess.Start(executable, args, pipe))
                {
                    var bytes = new byte[4096]; // Secret-free CONTROL pipe, never stdout/stderr.
                    for (;;)
                    {
                        uint available;
                        bool peek = Native.PeekNamedPipe(pipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero);
                        if (peek && available != 0)
                        {
                            int read = pipe.Read(bytes, 0, (int)Math.Min(available, (uint)bytes.Length));
                            for (int i = 0; i < read; i++)
                            {
                                if (bytes[i] == 10)
                                {
                                    string frame = line.ToString(); line.Length = 0;
                                    if (++frames > 256) { badProtocol = true; break; }
                                    try
                                    {
                                        if (frame.StartsWith("S:", StringComparison.Ordinal) && result == null)
                                        {
                                            int value;
                                            if (!Int32.TryParse(frame.Substring(2), out value) || !Enum.IsDefined(typeof(Stage), value)) throw new BrokerError("worker_protocol_failed");
                                            stage = (Stage)value; elapsed.Restart();
                                            if (stage == Stage.TargetResolved || stage == Stage.TargetOpen) resolved = true;
                                            if (diagnostic) Console.Error.WriteLine("[broker] " + Diagnostics.Name(stage));
                                        }
                                        else if (frame.StartsWith("R:", StringComparison.Ordinal) && result == null) result = ResultData.Parse(frame.Substring(2));
                                        else throw new BrokerError("worker_protocol_failed");
                                    }
                                    catch (Exception) { badProtocol = true; break; }
                                }
                                else if (bytes[i] < 32 || bytes[i] > 126 || line.Length >= 32768) { badProtocol = true; break; }
                                else line.Append((char)bytes[i]);
                            }
                            if (badProtocol) break;
                            continue;
                        }
                        if (worker.Wait(0))
                        {
                            if (Native.PeekNamedPipe(pipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero) && available != 0) continue;
                            break;
                        }
                        if (Volatile.Read(ref cancelRequested) != 0) { cancelled = true; break; }
                        if (!Diagnostics.UserWait(stage) && elapsed.ElapsedMilliseconds > deadlineMilliseconds) { timedOut = true; break; }
                        worker.Wait(25);
                    }
                    if (badProtocol || cancelled || timedOut) worker.Stop(timedOut ? 124u : 125u);
                    uint nativeExit = worker.ExitCode;
                    int targetIndex = args.Length > 0 && args[0] == "vmrun" ? 2 : 1;
                    string target = resolved && args.Length > targetIndex && Target.ValidName(args[targetIndex]) ? args[targetIndex] : null;
                    SupervisedResult answer = Classify(result, nativeExit, stage, timedOut, cancelled, badProtocol || line.Length != 0);
                    if (answer.Result.Target == null) answer.Result.Target = target;
                    return answer;
                }
            }
            finally { Console.CancelKeyPress -= cancel; }
        }

        internal static SupervisedResult Classify(ResultData result, uint exit, Stage stage, bool timedOut, bool cancelled, bool protocolError)
        {
            // WorkerMain intentionally exits124 for a returned, structured CLI
            // deadline. Do not overwrite that validated cause/stage as a native
            // watchdog failure merely because both use124. Outer failures still
            // take precedence; a success/error mismatch never becomes success.
            if (!protocolError && !cancelled && !timedOut && exit == 124 && result != null && !result.Ok && result.ErrorCode == "official_cli_timeout")
            {
                result.Validate(); return new SupervisedResult { Result = result, ExitCode = 124 };
            }
            string error = protocolError ? "worker_protocol_failed" : cancelled ? "operation_cancelled" : timedOut || exit == 124 ? "native_timeout" : null;
            int code = protocolError ? 4 : cancelled ? 125 : error != null ? 124 : 4;
            if (error == null && result != null && ((exit == 0 && result.Ok) || ((exit == 2 || exit == 3) && !result.Ok)))
                return new SupervisedResult { Result = result, ExitCode = (int)exit };
            if (error == null) error = exit == 0 ? "no_worker_result" : "native_worker_terminated";
            if (result != null && stage == Stage.Complete) stage = Stage.WorkerExit;
            var failure = ResultData.Error(error, stage);
            failure.NativeExit = "0x" + exit.ToString("X8");
            failure.Outcome = "unknown";
            return new SupervisedResult { Result = failure, ExitCode = code };
        }

        internal static void WatchParent(string handle)
        {
            long value;
            if (!Int64.TryParse(handle, out value) || value == 0 || value == -1) throw new BrokerError("worker_start_failed");
            var parent = new IntPtr(value);
            if (Native.WaitForSingleObject(parent, 0) != 258) throw new BrokerError("worker_start_failed");
            ThreadPool.QueueUserWorkItem(delegate
            {
                Native.WaitForSingleObject(parent, 0xffffffff);
                // No retry, dump, or guest/VM process termination. Only this worker.
                Native.TerminateProcess(new IntPtr(-1), 125);
            });
        }

        internal static int WorkerMain(string[] args)
        {
            Native.SetErrorMode(0x0001 | 0x0002 | 0x8000);
            WatchParent(args[2]);
            using (var pipe = new AnonymousPipeClientStream(PipeDirection.Out, args[1]))
            using (var writer = new StreamWriter(pipe, new UTF8Encoding(false)))
            {
                writer.NewLine = "\n"; writer.AutoFlush = true;
                Diagnostics.Channel = writer;
                int exit;
                ResultData result;
                try
                {
                    var command = new string[args.Length - 3]; Array.Copy(args, 3, command, 0, command.Length);
                    Request request = Request.Parse(command);
                    Diagnostics.At(Stage.Starting);
                    result = ResultData.Parse(Broker.Execute(request, new WindowsRuntime()));
                    exit = result.Ok ? 0 : 2;
                }
                catch (BrokerError error)
                {
                    result = ResultData.Error(error.Code, Diagnostics.Failure ?? Diagnostics.Current);
                    exit = error.Code == "official_cli_timeout" ? 124 : 2;
                    if (error.Code == "official_cli_timeout" || error.Code == "official_cli_failed" || error.Code == "private_export_limit" || error.Code == "guest_fixture_mutation_uncertain" || error.Code == "transfer_outcome_unknown" || error.Code == "public_share_outcome_unknown" || error.Code == "owned_clone_outcome_unknown" || error.Code == "clone_identity_outcome_unknown" || error.Code == "forward_outcome_unknown" || error.Code == "photon_download_outcome_unknown") result.Outcome = "unknown";
                }
                catch (Exception) { result = ResultData.Error("local_operation_failed", Diagnostics.Failure ?? Diagnostics.Current); exit = 3; }
                Diagnostics.At(Stage.Complete);
                writer.WriteLine("R:" + result.Json());
                Diagnostics.Channel = null;
                return exit;
            }
        }
    }
}
