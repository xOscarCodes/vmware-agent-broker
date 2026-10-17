using System;
using System.IO;

namespace GuestBroker
{
    // Only these fixed stage IDs cross the control pipe. No strings from APIs,
    // inputs, paths, accounts, native error text, or credential buffers.
    internal enum Stage
    {
        Starting, RegistryRead, RegistrationPrompt, RegistryWrite, NativeLoad,
        HostConnect, TargetOpen, TargetValidate, StatusRead, TimezoneConsent,
        CredentialPrompt, CredentialPromptReturned, CredentialUnpack, CredentialRead, CredentialUtf8,
        GuestLogin, GuestLoginWait, GuestIdentity, GuestProgram, GuestProgramWait,
        GuestLogout, VmRelease, HostDisconnect, CredentialSave, CredentialDelete,
        SecretCleanup, Complete, TargetResolved, WorkerExit, CapabilityRead, CapabilityPrompt, OperationConsent, CatalogOperation, HostReadConsent, CliVerify, CliCall, PrivateExport, ScriptRead, TransferCopy, CloneNativeComplete, CloneIdentity, ToolsWait
    }

    internal static class Diagnostics
    {
        internal static TextWriter Channel { get; set; }
        internal static Stage Current = Stage.Starting;
        internal static Stage? Failure;
        internal static int? FailedProperty, FailedActualType;
        internal static string FailedExpectedType;
        internal static bool SafeProperty(int property)
        { return Array.IndexOf(new[] { 51, 103, 129, 152, 3010, 3011, 3018, 3035, 3046, 3048, 3049, 3054, 3056, 3061, 4200 }, property) >= 0; }
        internal static void PropertyMismatch(int property, string expected, int actual)
        {
            if (!SafeProperty(property)) throw new BrokerError("worker_protocol_failed");
            Fault(); FailedProperty = property; FailedExpectedType = expected; FailedActualType = actual;
        }
        internal static void Fault() { if (!Failure.HasValue) Failure = Current; }
        internal static void At(Stage stage)
        {
            Current = stage;
            if (Channel != null) { Channel.WriteLine("S:" + (int)stage); Channel.Flush(); }
        }
        internal static bool UserWait(Stage stage)
        {
            return stage == Stage.RegistrationPrompt || stage == Stage.CredentialPrompt || stage == Stage.CapabilityPrompt; // Old operation-consent IDs remain historical, not user-wait states.
        }
        internal static string Name(Stage stage)
        {
            switch (stage)
            {
                case Stage.Starting: return "worker_start";
                case Stage.RegistryRead: return "registry_read";
                case Stage.TargetResolved: return "target_resolved";
                case Stage.RegistrationPrompt: return "registration_prompt";
                case Stage.RegistryWrite: return "registry_write";
                case Stage.NativeLoad: return "native_load";
                case Stage.HostConnect: return "host_connect";
                case Stage.TargetOpen: return "target_open";
                case Stage.TargetValidate: return "target_validate";
                case Stage.StatusRead: return "status_read";
                case Stage.TimezoneConsent: return "timezone_consent";
                case Stage.CredentialPrompt: return "credential_prompt";
                case Stage.CredentialPromptReturned: return "credential_prompt_return";
                case Stage.CredentialUnpack: return "credential_unpack";
                case Stage.CredentialRead: return "credential_read";
                case Stage.CredentialUtf8: return "credential_utf8";
                case Stage.GuestLogin: return "guest_login_call";
                case Stage.GuestLoginWait: return "guest_login_wait";
                case Stage.GuestIdentity: return "guest_identity";
                case Stage.GuestProgram: return "guest_program_call";
                case Stage.GuestProgramWait: return "guest_program_wait";
                case Stage.GuestLogout: return "guest_logout";
                case Stage.VmRelease: return "vm_release";
                case Stage.HostDisconnect: return "host_disconnect";
                case Stage.CredentialSave: return "credential_save";
                case Stage.CredentialDelete: return "credential_delete";
                case Stage.SecretCleanup: return "secret_cleanup";
                case Stage.Complete: return "complete";
                case Stage.WorkerExit: return "worker_exit";
                case Stage.CapabilityRead: return "capability_read";
                case Stage.CapabilityPrompt: return "capability_prompt";
                case Stage.OperationConsent: return "operation_consent";
                case Stage.CatalogOperation: return "catalog_operation";
                case Stage.HostReadConsent: return "host_read_consent";
                case Stage.CliVerify: return "cli_verify";
                case Stage.CliCall: return "cli_call";
                case Stage.PrivateExport: return "private_export";
                case Stage.ScriptRead: return "script_read";
                case Stage.TransferCopy: return "transfer_copy";
                case Stage.CloneNativeComplete: return "clone_native_completed";
                case Stage.CloneIdentity: return "clone_identity_initialize";
                case Stage.ToolsWait: return "tools_wait_same_handle";
                default: throw new BrokerError("worker_protocol_failed");
            }
        }
    }
}
