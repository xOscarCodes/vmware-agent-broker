namespace GuestBroker
{
    // Fixed public ABI operation selection, NOT caller-selected symbols or DLLs.
    internal static class NativePlans
    {
        internal const int RequireInteractiveEnvironment = 0x08;
        internal const int ActivateOwnedFixtureWindow = 0x0002;
        internal const string FixtureLaunchMode = "native_login8_activate2_waiting_launcher";
        internal static int LoginOptions(VmrunRequest request)
        {
            if (request == null || !request.IsFixtureStart) return 0;
            if (request.Arguments.Length != 3 || !FixtureProtocol.Alias(request.Arguments[1])) throw new BrokerError("invalid_request");
            GuestProcessSupervisor.Slot(request.Arguments[2]);
            return RequireInteractiveEnvironment;
        }
        internal static bool NeedsGuest(string name) { return name == "runProgramInGuest" || name == "runScriptInGuest" || name == "listProcessesInGuest" || name == "readVariable" || GuestFixture.Command(name) || PublicTransfers.Command(name); }
        internal static string GuestCategory(string name) { return name == "readVariable" ? "depends" : NeedsGuest(name) ? "required" : "no"; }
        internal static bool MetadataOnly(string name) { return name == "list" || name == "listSnapshots" || name == "checkToolsState"; }
        internal static bool Disposable(string name) { return !MetadataOnly(name) && name != "listProcessesInGuest" && name != "readVariable"; }
        internal static string Symbol(VmrunRequest request)
        {
            switch (request.Entry.Name)
            {
                case "start": return "VixVM_PowerOn";
                case "stop": return "VixVM_PowerOff";
                case "reset": return "VixVM_Reset";
                case "suspend": return "VixVM_Suspend";
                case "pause": return "VixVM_Pause";
                case "unpause": return "VixVM_Unpause";
                case "snapshot": return "VixVM_CreateSnapshot";
                case "listSnapshots": return "VixVM_GetNumRootSnapshots";
                case "deleteSnapshot": return "VixVM_RemoveSnapshot";
                case "revertToSnapshot": return "VixVM_RevertToSnapshot";
                case "runProgramInGuest": return "VixVM_RunProgramInGuest";
                case "runScriptInGuest": return "VixVM_RunProgramInGuest";
                case "CopyFileFromHostToGuest": return "VixVM_CopyFileFromHostToGuest";
                case "CopyFileFromGuestToHost": return "VixVM_CopyFileFromGuestToHost";
                case "addSharedFolder": return "VixVM_AddSharedFolder";
                case "setSharedFolderState": return "VixVM_SetSharedFolderState";
                case "enableSharedFolders": return "VixVM_EnableSharedFolders";
                case "clone": return "VixVM_Clone";
                case "deleteVM": return "VixVM_Delete";
                case "fileExistsInGuest": case "directoryExistsInGuest": case "createDirectoryInGuest": case "CreateTempfileInGuest": case "listDirectoryInGuest": case "renameFileInGuest": case "deleteFileInGuest": case "deleteDirectoryInGuest": case "killProcessInGuest": case "typeKeystrokesInGuest": return "VixVM_RunProgramInGuest";
                case "listProcessesInGuest": return "VixVM_ListProcessesInGuest";
                case "readVariable": return "VixVM_ReadVariable";
                case "writeVariable": return "VixVM_WriteVariable";
                case "installTools": return "VixVM_InstallTools";
                case "checkToolsState": case "list": return "Vix_GetProperties";
                default: throw new BrokerError("catalog_operation_unavailable");
            }
        }
        internal static int Flags(VmrunRequest request)
        {
            switch (request.Entry.Name)
            {
                case "start": return request.Arguments[0] == "gui" ? 0x200 : 0;
                case "stop": case "reset": case "suspend": return request.Arguments[0] == "soft" ? 4 : 0;
                case "deleteSnapshot": return request.Arguments.Length == 2 ? 1 : 0;
                case "installTools": return ToolsReadiness.MountOnlyReturnImmediately;
                case "runProgramInGuest": return LoginOptions(request) == RequireInteractiveEnvironment ? ActivateOwnedFixtureWindow : 0;
                default: return 0;
            }
        }
    }
}
