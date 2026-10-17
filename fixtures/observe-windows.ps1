# Public non-secret read-only smoke fixture; prints no machine/account data.
$ErrorActionPreference = 'Stop'
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    exit 11
}
if ([System.Environment]::MachineName -notmatch '^[A-Za-z0-9-]{1,63}$') {
    exit 12
}
exit 0
