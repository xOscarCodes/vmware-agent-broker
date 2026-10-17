param([switch]$Test)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Windows .NET Framework x86 compiler required.' }
$out = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$helperSources = @('BrokerError.cs', 'Diagnostics.cs', 'UiText.cs', 'Native.cs', 'ProcessNative.cs', 'JobNative.cs', 'WindowsArguments.cs', 'HostPaths.cs', 'OwnedNative.cs', 'GuestOwned.cs', 'GuestRename.cs', 'GuestDelete.cs', 'GeneratedFixture.cs', 'ApprovedListing.cs', 'GuestListing.cs', 'GuestProcessNative.cs', 'GuestProcessStore.cs', 'GuestProcessSupervisor.cs', 'PublicFixtureSink.cs', 'GuestHelperCore.cs', 'GuestHelperProgram.cs') | ForEach-Object { Join-Path $PSScriptRoot "src\$_" }
& $compiler /nologo /platform:x86 /define:GUEST_HELPER /optimize+ /checked+ /warn:4 /warnaserror+ /target:exe /reference:System.Runtime.Serialization.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /main:GuestBroker.GuestHelperProgram "/out:$out\broker-guest-helper.exe" $helperSources
if ($LASTEXITCODE -ne 0) { throw 'Guest helper compilation failed.' }
$helperHashFile = Join-Path $out 'helper-image-sha256.txt'
(Get-FileHash -LiteralPath (Join-Path $out 'broker-guest-helper.exe') -Algorithm SHA256).Hash | Set-Content -LiteralPath $helperHashFile -Encoding ascii
$helperResource = '/resource:' + $helperHashFile + ',GuestBroker.HelperImageSha256'
$sources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName)
$catalog = '/resource:' + (Join-Path $PSScriptRoot 'coverage\vmrun-coverage.json') + ',GuestBroker.Catalog'
& $compiler /nologo /platform:x86 /unsafe /optimize+ /checked+ /warn:4 /warnaserror+ /target:exe /reference:System.Runtime.Serialization.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll $catalog $helperResource /main:GuestBroker.Program "/out:$out\guest-broker.exe" $sources
if ($LASTEXITCODE -ne 0) { throw 'Broker compilation failed.' }
if ($Test) {
    & $compiler /nologo /platform:x86 /define:BROKER_TESTS /unsafe /optimize+ /checked+ /warn:4 /warnaserror+ /target:exe /reference:System.Runtime.Serialization.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll $catalog $helperResource /main:GuestBroker.Tests "/out:$out\broker-tests.exe" $sources (Join-Path $PSScriptRoot 'tests\Tests.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }
    & "$out\broker-tests.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}
