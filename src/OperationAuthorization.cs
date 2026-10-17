using System;

namespace GuestBroker
{
    // Current owner direction: operation prompts are DEFERRED, not auto-clicked
    // or replaced with --yes. Scope/identity/ownership/credential setup still bind.
    internal static class OperationAuthorization
    {
        internal const string PromptStatus = "deferred-policy-required";
        internal static bool RequiresPrompt { get { return false; } }
        internal static VmAuthorization ForVm(IBrokerRuntime runtime, ICatalogRuntime permissions, Target target, VmrunRequest request)
        { return new VmAuthorization(runtime, permissions, target, request, false); }
        internal static VmAuthorization ForTimezone(IBrokerRuntime runtime, Target target)
        {
            var permissions = runtime as ICatalogRuntime;
            if (permissions == null) throw new BrokerError("capability_policy_invalid");
            return new VmAuthorization(runtime, permissions, target, null, true);
        }
        internal static void HostRead(VmrunRequest request)
        {
            // Preconfigured local-machine READ scope from the current owner task.
            // This is not a VM permission or a host-write policy. Fixed local tool
            // hashes/signatures and bounded public-only parsers remain mandatory.
            if (request.Entry.TargetScoped || request.NeedsCredential) throw new BrokerError("cli_plan_forbidden");
            if (request.Entry.Name == "listHostNetworks" && request.Arguments.Length == 0) return;
            if (request.Entry.Name == "listPortForwardings" && request.Arguments.Length == 1) { CliParsing.NetworkName(request.Arguments[0]); return; }
            throw new BrokerError("catalog_operation_unavailable"); // Future writes require their own machine-owner implementation/policy.
        }
    }
    internal sealed class VmAuthorization
    {
        private readonly IBrokerRuntime runtime;
        private readonly ICatalogRuntime permissions;
        private readonly Target target;
        private readonly VmrunRequest request;
        private readonly bool timezone;
        private readonly string fingerprint;
        internal CapabilityProfile Profile { get; private set; }
        internal VmAuthorization(IBrokerRuntime runtime, ICatalogRuntime permissions, Target target, VmrunRequest request, bool timezone)
        {
            this.runtime = runtime; this.permissions = permissions; this.target = target; this.request = request; this.timezone = timezone;
            Profile = permissions.Capabilities(target); Demand(Profile); fingerprint = Profile.Fingerprint(); permissions.ValidateTarget(target);
        }
        private void Demand(CapabilityProfile profile) { if (timezone) profile.DemandTimezone(target); else profile.Demand(target, request); }
        internal void Revalidate()
        {
            if (!target.SameRegistrationVersion(runtime.Resolve(target.Name))) throw new BrokerError("capability_policy_changed");
            CapabilityProfile current = permissions.Capabilities(target);
            if (current.Fingerprint() != fingerprint) throw new BrokerError("capability_policy_changed");
            Demand(current); permissions.ValidateTarget(target);
        }
    }
}
