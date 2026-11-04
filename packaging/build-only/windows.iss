#if (PREPROCVER & 0xFFFFFF00) != 0x06070100
#error Inno Setup 6.7.1 compiler engine required
#endif
#ifndef StageDir
#error StageDir required
#endif
#ifndef OutputDir
#error OutputDir required
#endif
#ifndef ReleaseVersion
#error ReleaseVersion required
#endif
#ifndef NumericVersion
#error NumericVersion required
#endif
[Setup]
AppId={{770BD6FD-3880-4614-9288-994EFD7B51FA}
AppName=Meridian Windows Preview
AppVersion={#ReleaseVersion}
AppVerName=Meridian {#ReleaseVersion} Windows Preview
AppPublisher=Meridian
DefaultDirName={localappdata}\Programs\Meridian Preview
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=Meridian-{#ReleaseVersion}-Windows-x64-Setup
SetupIconFile={#StageDir}\meridian.ico
UninstallDisplayIcon={app}\meridian.ico
VersionInfoVersion={#NumericVersion}
VersionInfoProductVersion={#NumericVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
InfoBeforeFile={#StageDir}\安装说明.md
CloseApplications=no
RestartApplications=no
Uninstallable=yes
[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{userprograms}\Meridian Preview\Meridian"; Filename: "{app}\meridian.exe"; IconFilename: "{app}\meridian.ico"
Name: "{userprograms}\Meridian Preview\卸载 Meridian"; Filename: "{uninstallexe}"
Name: "{userprograms}\Meridian Preview\实验性 Windows 既有 VPN 模式"; Filename: "{app}\meridian.exe"; Parameters: "--enable-windows-borrowed"; IconFilename: "{app}\meridian.ico"
Name: "{userprograms}\Meridian Preview\使用限制"; Filename: "{app}\安装说明.md"
