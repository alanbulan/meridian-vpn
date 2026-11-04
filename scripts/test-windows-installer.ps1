param([Parameter(Mandatory=$true)][string]$ArtifactDirectory)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'Disposable Windows Actions runner required' }
$artifact=[IO.Path]::GetFullPath($ArtifactDirectory)
$setup=Join-Path $artifact 'Meridian-0.1.0-alpha.1-Windows-x64-Setup.exe'
$manifest=Get-Content (Join-Path $artifact 'build-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.source_commit -ne $env:GITHUB_SHA -or $manifest.vpn_backend_usable -ne $false) { throw 'Wrong artifact source or capability claim' }
$expected=(Get-Content (Join-Path $artifact 'SHA256SUMS-windows') -Raw).Split(' ')[0]
if ((Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Setup checksum mismatch' }
$install=Join-Path $env:RUNNER_TEMP "Meridian-Installer-$env:GITHUB_RUN_ID"
if (Test-Path $install) { throw 'Test installation already exists' }
$logs=Join-Path $env:RUNNER_TEMP 'meridian-installer-logs'; New-Item -ItemType Directory -Path $logs -Force | Out-Null
$arguments=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',"/DIR=`"$install`"", "/LOG=`"$logs/install.log`"")
$process=Start-Process -FilePath $setup -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Installation failed: $($process.ExitCode)" }
foreach ($file in $manifest.files) {
    $path=Join-Path $install $file.name
    if (!(Test-Path $path) -or (Get-Item $path).Length -ne $file.bytes -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw "Installed file mismatch: $($file.name)" }
}
$uninstallKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{770BD6FD-3880-4614-9288-994EFD7B51FA}_is1'
if (!(Test-Path $uninstallKey)) { throw 'Per-user uninstall registration missing' }
if (Test-Path $uninstallKey.Replace('HKCU:','HKLM:')) { throw 'Unexpected machine-wide uninstall registration' }
$startMenu=Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Meridian Preview\Meridian.lnk'
if (!(Test-Path $startMenu)) { throw 'Start menu shortcut missing' }
$shell=New-Object -ComObject WScript.Shell
if ($shell.CreateShortcut($startMenu).TargetPath -ne (Join-Path $install 'meridian.exe')) { throw 'Wrong shortcut target' }
if (Test-Path (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Meridian Preview.lnk')) { throw 'Desktop shortcut unexpectedly selected' }
$cliOutput=& (Join-Path $install 'meridianctl.exe') version
if ($LASTEXITCODE -ne 0 -or $cliOutput.Trim() -ne 'Meridian CLI 0.1.0-alpha.1') { throw 'Installed CLI version mismatch' }
$versionOut=Join-Path $logs 'gui-version.txt'
$versionProcess=Start-Process -FilePath (Join-Path $install 'meridian.exe') -ArgumentList '--version' -RedirectStandardOutput $versionOut -Wait -PassThru
if ($versionProcess.ExitCode -ne 0 -or (Get-Content $versionOut -Raw).Trim() -ne "Meridian 0.1.0-alpha.1 ($env:GITHUB_SHA)") { throw 'Installed GUI version/source mismatch' }
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class InstallerWindowCheck {
 [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr handle);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr handle, out RECT rect);
}
'@
$config=Join-Path $logs 'profiles.json'
[IO.File]::WriteAllText($config,'{"version":1,"profiles":[],"settings":{"minimize_to_tray":false,"language":"en"}}',[Text.UTF8Encoding]::new($false))
$gui=Start-Process -FilePath (Join-Path $install 'meridian.exe') -ArgumentList @('--config',"`"$config`"") -PassThru
try {
    $visible=$false
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1; $gui.Refresh()
        if ($gui.HasExited) { throw 'GUI exited before creating a window' }
        $handle=$gui.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero -and [InstallerWindowCheck]::IsWindowVisible($handle)) {
            $rect=[InstallerWindowCheck+RECT]::new()
            if ([InstallerWindowCheck]::GetWindowRect($handle,[ref]$rect) -and ($rect.Right-$rect.Left) -ge 800 -and ($rect.Bottom-$rect.Top) -ge 500) { $visible=$true; break }
        }
    }
    if (!$visible) { throw 'No visible process-owned main window with expected minimum dimensions' }
    Write-Output "Visible installed GUI: $($gui.MainWindowTitle), $($rect.Right-$rect.Left)x$($rect.Bottom-$rect.Top)"
    if (!$gui.CloseMainWindow() -or !$gui.WaitForExit(15000)) { throw 'Unconnected GUI did not close normally' }
} finally {
    if (!$gui.HasExited) { Stop-Process -Id $gui.Id -Force }
}
# No credentials/profiles were configured. Uninstall must preserve unrelated
# user-owned data; the installer has no UninstallDelete wildcard or service.
$userData=Join-Path $env:APPDATA 'meridian'
New-Item -ItemType Directory -Path $userData -Force | Out-Null
$sentinel=Join-Path $userData 'installer-test-sentinel.txt'
[IO.File]::WriteAllText($sentinel,'preserve user data')
$uninstaller=Join-Path $install 'unins000.exe'
$process=Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/LOG=`"$logs/uninstall.log`"") -Wait -PassThru
if ($process.ExitCode -ne 0) { throw 'Uninstall failed' }
for ($i=0; $i -lt 15 -and (Test-Path $uninstaller); $i++) { Start-Sleep 1 }
if ((Test-Path (Join-Path $install 'meridian.exe')) -or (Test-Path $startMenu) -or (Test-Path $uninstallKey)) { throw 'Uninstall left registered application files' }
if (!(Test-Path $sentinel)) { throw 'Uninstall removed personal data' }
Write-Output 'PASS: Setup.exe installation, exact hashes/version, per-user registration, visible native window and normal close, uninstall and user-data preservation. Windows VPN remains unavailable.'
