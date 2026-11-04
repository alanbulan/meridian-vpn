param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (!(Test-Path Env:GITHUB_SHA) -or $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') { throw 'Exact source commit required' }
if ((git rev-parse HEAD).Trim() -ne $env:GITHUB_SHA) { throw 'Checkout provenance mismatch' }
if (git status --porcelain --untracked-files=normal) { throw 'Clean source checkout required' }
$env:CGO_ENABLED='0'; $env:GOTOOLCHAIN='local'; $env:GOWORK='off'; $env:GOENV='off'; $env:GOAMD64='v1'
if ($env:GOFLAGS -or $env:GOEXPERIMENT) { throw 'Custom compiler flags prohibited' }
$iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
if (!(Test-Path $iscc)) { throw 'Official runner Inno Setup compiler missing; no automatic download' }
$compiler = Get-Item $iscc
$signature = Get-AuthenticodeSignature $iscc
Write-Output "Compiler metadata: FileVersion=$($compiler.VersionInfo.FileVersion); ProductVersion=$($compiler.VersionInfo.ProductVersion); Signature=$($signature.Status); SHA256=$((Get-FileHash $iscc -Algorithm SHA256).Hash)"
if ($compiler.VersionInfo.FileVersion -notmatch '^6\.7\.1(?:\D|$)') { throw "Unexpected compiler file version: $($compiler.VersionInfo.FileVersion)" }
if ($signature.Status -ne 'Valid') { throw "Installer compiler signature is not valid: $($signature.Status)" }
if ($signature.SignerCertificate.Subject -notmatch 'Jordan Russell|JRSoftware|jrsoftware') { throw 'Unexpected installer compiler signer' }
$out = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $out) { throw 'Output directory already exists' }
$stage = Join-Path $root 'build/windows-installer-stage'
if (Test-Path $stage) { throw 'Installer staging directory already exists' }
New-Item -ItemType Directory -Path $stage,$out | Out-Null
& go mod verify; if ($LASTEXITCODE) { throw 'Module verification failed' }
$flags = "-s -w -X mygo-vpn/internal/buildinfo.Version=0.1.0-alpha.1 -X mygo-vpn/internal/buildinfo.Commit=$env:GITHUB_SHA"
& go build -buildvcs=false -trimpath -mod=readonly -tags mygo_noinspector -ldflags "$flags -H=windowsgui -X github.com/egoist/mygo.production=1" -o "$stage/meridian.exe" ./cmd/meridian
if ($LASTEXITCODE) { throw 'GUI build failed' }
& go build -buildvcs=false -trimpath -mod=readonly -ldflags $flags -o "$stage/meridianctl.exe" ./cmd/meridianctl
if ($LASTEXITCODE) { throw 'CLI build failed' }
& git archive --format=tar -o "$stage/source.tar" $env:GITHUB_SHA
if ($LASTEXITCODE) { throw 'Source snapshot failed' }
Copy-Item THIRD_PARTY.md $stage
Copy-Item docs/third-party "$stage/licenses-go" -Recurse
Copy-Item docs/MYGO-LICENSE.txt $stage
Copy-Item internal/desktop/assets/lucide/LICENSE "$stage/LUCIDE-LICENSE.txt"
$text = Get-Content packaging/windows/WINDOWS-PREVIEW.txt -Raw -Encoding utf8
[IO.File]::WriteAllText("$stage/WINDOWS-PREVIEW.txt", $text, [Text.UTF8Encoding]::new($true))
# ICO wraps the existing licensed PNG bytes; no new downloaded image/tool.
$png = [IO.File]::ReadAllBytes('internal/desktop/assets/lucide/tray-network.png')
if ($png[0] -ne 137 -or $png[1] -ne 80 -or $png[2] -ne 78 -or $png[3] -ne 71) { throw 'Invalid icon PNG' }
$width=[int]$png[19]; $height=[int]$png[23]
if ($width -le 0 -or $height -le 0 -or $png[16] -ne 0 -or $png[17] -ne 0 -or $png[18] -ne 0 -or $png[20] -ne 0 -or $png[21] -ne 0 -or $png[22] -ne 0) { throw 'Unsupported icon dimensions' }
$stream=[IO.MemoryStream]::new(); $writer=[IO.BinaryWriter]::new($stream)
$writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]1)
$writer.Write([byte]$width);$writer.Write([byte]$height);$writer.Write([byte]0);$writer.Write([byte]0)
$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$png.Length);$writer.Write([uint32]22);$writer.Write($png)
[IO.File]::WriteAllBytes("$stage/meridian.ico",$stream.ToArray());$writer.Dispose();$stream.Dispose()
$files=@(Get-ChildItem $stage -File -Recurse | Sort-Object FullName | ForEach-Object { @{name=[IO.Path]::GetRelativePath($stage,$_.FullName).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
$manifest=@{version='0.1.0-alpha.1';source_commit=$env:GITHUB_SHA;target='windows-amd64';distribution='unsigned-experimental-preview';vpn_backend_usable=$false;go=(& go version);installer_compiler_version=$compiler.VersionInfo.FileVersion;installer_compiler_sha256=(Get-FileHash $iscc -Algorithm SHA256).Hash.ToLowerInvariant();installer_compiler_signer=$signature.SignerCertificate.Subject;files=$files;limits='Installer and UI validation only; Windows VPN backend incomplete, no live VPN acceptance, no bundled MFA helper, no license selected.'}
$manifest | ConvertTo-Json -Depth 8 | Set-Content "$stage/build-manifest.json" -Encoding utf8
& $iscc "/DStageDir=$stage" "/DOutputDir=$out" packaging/windows/meridian.iss
if ($LASTEXITCODE) { throw 'Installer compilation failed' }
$setup=Join-Path $out 'Meridian-0.1.0-alpha.1-Windows-x64-Setup.exe'
if (!(Test-Path $setup)) { throw 'Installer missing' }
if ((Get-Item $setup).VersionInfo.FileVersion -ne '0.1.0.1') { throw 'Installer version mismatch' }
Copy-Item "$stage/build-manifest.json" $out
Copy-Item "$stage/WINDOWS-PREVIEW.txt" $out
$hash=(Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$out/SHA256SUMS-windows", "$hash  $([IO.Path]::GetFileName($setup))`n", [Text.UTF8Encoding]::new($false))
if ((git rev-parse HEAD).Trim() -ne $env:GITHUB_SHA -or (git status --porcelain --untracked-files=normal)) { throw 'Source changed during build' }
Write-Output "Built unsigned experimental Setup.exe: $hash"
