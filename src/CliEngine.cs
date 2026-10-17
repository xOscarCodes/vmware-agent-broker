using System;
using System.IO;

namespace GuestBroker
{
    internal interface IOfficialCliRuntime
    {
        OperationReport ExecuteOfficialCli(VmrunRequest request, Target target, CapabilityProfile profile);
    }
    internal static class CliEngine
    {
        internal static string Execute(VmrunRequest request, IBrokerRuntime runtime, ICatalogRuntime permissions)
        {
            var official = runtime as IOfficialCliRuntime;
            if (official == null || request.NeedsCredential) throw new BrokerError("cli_plan_forbidden");
            if (!request.Entry.TargetScoped)
            {
                if (request.Entry.Name != "listHostNetworks" && request.Entry.Name != "listPortForwardings") throw new BrokerError("catalog_operation_unavailable");
                OperationAuthorization.HostRead(request);
                OperationReport host = official.ExecuteOfficialCli(request, null, null); host.Validate();
                return new ResultData { Ok = true, Operation = host }.Json();
            }
            Target target = runtime.Resolve(request.TargetName); Diagnostics.At(Stage.TargetResolved);
            VmAuthorization authorization = OperationAuthorization.ForVm(runtime, permissions, target, request);
            CapabilityProfile profile = authorization.Profile; authorization.Revalidate();
            OperationReport report = official.ExecuteOfficialCli(request, target, profile); report.Validate();
            return new ResultData { Ok = true, Target = target.Name, Operation = report }.Json();
        }
        internal static OperationReport Real(VmrunRequest request, Target target, CapabilityProfile profile)
        {
            if (request.NeedsCredential) throw new BrokerError("cli_plan_forbidden");
            if (target == null)
            {
                OperationAuthorization.HostRead(request);
                using (CliReply reply = CliTools.Run(CliPlan.Build(request, null, null), null)) return CliParsing.Parse(request, reply);
            }
            profile.Demand(target, request);
            if (request.Entry.Name == "upgradevm")
            {
                return UpgradeWithoutPins(target, delegate
                {
                    using (CliReply reply = CliTools.Run(CliPlan.Build(request, target, null), null))
                    {
                        if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
                        var report = OperationReport.New(request); report.Completion = "cli_completed_not_verified"; return report;
                    }
                });
            }
            using (PinnedDirectory vmDirectory = PinnedDirectory.Open(Path.GetDirectoryName(target.Vmx)))
            using (FileStream targetPin = VmIdentity.Open(target))
            {
                if (request.Entry.Name == "captureScreen")
                {
                    using (PrivateCapture export = PrivateCapture.Create(target, profile.Export))
                    using (CliReply reply = CliTools.Run(CliPlan.Build(request, target, export.FilePath), export.WithinLimit))
                    {
                        if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
                        var result = OperationReport.New(request); result.Completion = "private_export_header_checked";
                        result.Artifact = export.Id; result.ArtifactBytes = export.ValidateCompleted(); return result;
                    }
                }
                if (request.Entry.Name == "connectNamedDevice" || request.Entry.Name == "disconnectNamedDevice")
                {
                    // Keep VMX and its ancestors pinned even if that makes a vendor
                    // persistence writer fail. Never weaken identity binding to
                    // bypass sharing errors. Public runtime behavior remains live-gated.
                    ApprovedDevice device = profile.Device(request.Arguments[0]);
                    using (PinnedDirectory mediaDirectory = PinnedDirectory.Open(Path.GetDirectoryName(device.MediaPath)))
                    using (FileStream media = DeviceBinding.Validate(target, device))
                    using (CliReply reply = CliTools.Run(CliPlan.Build(request, target, null), null))
                    {
                        if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
                        var result = OperationReport.New(request); result.Completion = "cli_completed_not_verified"; result.Device = request.Arguments[0]; return result;
                    }
                }
                if (request.Entry.Name == "removeSharedFolder" || request.Entry.Name == "disableSharedFolders")
                {
                    using (CliReply reply = CliTools.Run(CliPlan.Build(request, target, null), null))
                    {
                        if (reply.Exit != 0) throw new BrokerError("official_cli_failed");
                        var result = OperationReport.New(request); result.Completion = "cli_completed_not_verified"; return result;
                    }
                }
                using (CliReply reply = CliTools.Run(CliPlan.Build(request, target, null), null)) return CliParsing.Parse(request, reply);
            }
        }
        internal static OperationReport UpgradeWithoutPins(Target target, Func<OperationReport> invoke)
        {
            // Parent actually observed native UpgradeVirtualHardware error15 while
            // immediate official vmrun upgrade succeeded with the VM stopped.
            // No native VM session and NO config/directory pin survive this check.
            using (VmIdentity.Open(target)) { }
            return invoke(); // Trusted VMware management writer, not atomic attestation.
        }
    }
}
