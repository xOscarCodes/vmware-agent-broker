using System;
using System.Collections.Generic;
using System.IO;

namespace GuestBroker
{
    internal interface IHostOperationsRuntime { OperationReport ExecuteHostOperation(VmrunRequest request); }
    internal interface INonsecretSetupRuntime { ResultData Setup(Request request); }
    internal static class HostOperations
    {
        internal static bool Command(string name) { return OwnedForwarding.Command(name) || name == "downloadPhotonVM"; }
        internal static OperationReport Real(VmrunRequest request)
        {
            var result = OperationReport.New(request); var store = new HostMetadata();
            if (OwnedForwarding.Command(request.Entry.Name)) OwnedForwarding.Execute(request, store, new ForwardNative(), DateTime.UtcNow, result);
            else if (request.Entry.Name == "downloadPhotonVM") PhotonDownload.Execute(store, new OfficialPhotonSource(), result);
            else throw new BrokerError("catalog_operation_unavailable");
            return result;
        }
    }
    internal static class NonsecretSetup
    {
        internal static ResultData Execute(Request request, RegistryStore registry, HostMetadata host, IForwardNative network)
        {
            string[] args = request.SetupArguments;
            var result = new ResultData { Ok = true };
            if (request.Operation == "setup-clones")
            {
                Target target = registry.Read().Resolve(args[0]);
                if (target.Name == "SAFE-DC") throw new BrokerError("protected_target_refused");
                if (target.Binding != args[3]) throw new BrokerError("registration_changed");
                using (VmIdentity.Open(target))
                {
                    CapabilityProfile profile = registry.ReadPolicy(target); if (!profile.Disposable) throw new BrokerError("disposable_target_required");
                    ExportRoot root = ExportRoot.Capture(args[1]); OwnedClones.Parent(target, root);
                    profile.CloneParent = root; if (!profile.Commands.Contains("clone")) profile.Commands.Add("clone"); profile.Revision = Guid.NewGuid().ToString("N").ToUpperInvariant(); registry.WritePolicy(target, profile);
                }
                result.Target = target.Name; result.SetupSaved = "clone_root";
            }
            else if (request.Operation == "register-clone")
            {
                Target source = registry.Read().Resolve(args[0]); CapabilityProfile sourcePolicy = registry.ReadPolicy(source); OwnedClones.Parent(source, sourcePolicy.CloneParent);
                if (!Target.ValidName(args[2]) || args[2] == "SAFE-DC" || args[2] == source.Name) throw new BrokerError("owned_clone_refused");
                using (host.Lock()) using (PinnedDirectory parent = PinnedDirectory.Open(sourcePolicy.CloneParent.Path))
                {
                    if (parent.Identity != sourcePolicy.CloneParent.Identity) throw new BrokerError("export_root_identity_changed");
                    CloneRecord record = OwnedClones.Read(host, args[1]);
                    if (record.State != "ready" || record.SourceBinding != source.Binding || record.Root.Path != Path.Combine(parent.Path, "clone-" + record.Id)) throw new BrokerError("owned_clone_refused");
                    Target target = registry.Read().Targets.Find(delegate(Target item) { return item.Name == args[2]; }); bool add = target == null;
                    if (add) target = VmIdentity.Capture(args[2], record.Vmx);
                    if (target.Vmx != record.Vmx || target.Uuid != record.Uuid || target.Binding == source.Binding || record.RegisteredBinding != null && record.RegisteredBinding != target.Binding && !add) throw new BrokerError("owned_clone_refused");
                    record.RegisteredBinding = target.Binding; OwnedClones.ValidateCurrent(record, target);
                    if (add) registry.Add(target);
                    host.Write("clone-" + record.Id + ".json", record);
                    CapabilityProfile profile = registry.ReadPolicy(target); profile.Disposable = true; profile.OwnedCloneId = record.Id;
                    if (!profile.Commands.Contains("deleteVM")) profile.Commands.Add("deleteVM"); profile.Revision = Guid.NewGuid().ToString("N").ToUpperInvariant(); registry.WritePolicy(target, profile);
                    result.Target = target.Name; result.SetupSaved = "clone_registered"; result.SetupId = record.Id;
                }
            }
            else if (request.Operation == "finalize-clone")
            {
                Target source = registry.Read().Resolve(args[0]); CapabilityProfile profile = registry.ReadPolicy(source);
                profile.Demand(source, VmrunRequest.Parse(new[] { "clone", source.Name, "full" }));
                CloneRecord record = OwnedClones.FinalizePrepared(source, profile.CloneParent, args[1], registry.Read().Targets, host, delegate(string temp, string destination) { File.Replace(temp, destination, null); });
                result.Target = source.Name; result.SetupSaved = "clone_finalized"; result.SetupId = record.Id; result.SetupProof = record.CopyProof;
            }
            else if (request.Operation == "network-baseline")
            {
                if (!network.IsNat(args[0])) throw new BrokerError("forward_scope_refused"); ForwardSnapshot snapshot = network.Read(args[0]);
                if (snapshot.Network != args[0]) throw new BrokerError("forward_snapshot_invalid");
                result.SetupSaved = "network_baseline"; result.SnapshotDigest = snapshot.Digest(); result.SetupCount = snapshot.Rows.Count;
            }
            else if (request.Operation == "setup-forwarding")
            {
                ForwardPolicy policy = OwnedForwarding.Configure(host, network, args[0], OwnedForwarding.CanonicalPort(args[1], true), args[2], OwnedForwarding.CanonicalPort(args[3], false), args[4], args[5], DateTime.UtcNow);
                result.SetupSaved = "forward_policy"; result.SetupId = policy.Id; result.SnapshotDigest = policy.Original.Digest();
            }
            else if (request.Operation == "setup-photon")
            {
                var policy = new PhotonPolicy { Machine = host.MachineBinding, Root = ExportRoot.Capture(args[0]), ExistingLicenseEvidence = args.Length == 5 ? args[2] : null, LicenseHash = args.Length == 5 ? args[4] : null };
                policy.Validate(host.MachineBinding); using (host.Lock()) host.Write("photon.json", policy);
                result.SetupSaved = "photon_root";
            }
            else throw new BrokerError("invalid_request");
            return result;
        }
    }
}
