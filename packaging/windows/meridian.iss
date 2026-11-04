; Per-user preview installer. No service, driver, firewall, network or autostart.
#ifndef StageDir
  #error StageDir required
#endif
#ifndef OutputDir
  #error OutputDir required
#endif
[Setup]
AppId={{770BD6FD-3880-4614-9288-994EFD7B51FA}
AppName=Meridian Windows Preview
AppVersion=0.1.0-alpha.1
AppVerName=Meridian 0.1.0-alpha.1 Windows Preview
AppPublisher=Meridian
AppPublisherURL=https://github.com/alanbulan/meridian-vpn
DefaultDirName={localappdata}\Programs\Meridian Preview
DefaultGroupName=Meridian Preview
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=Meridian-0.1.0-alpha.1-Windows-x64-Setup
SetupIconFile={#StageDir}\meridian.ico
UninstallDisplayIcon={app}\meridian.ico
VersionInfoVersion=0.1.0.1
VersionInfoProductVersion=0.1.0.1
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
InfoBeforeFile={#StageDir}\WINDOWS-PREVIEW.txt
CloseApplications=no
RestartApplications=no
Uninstallable=yes
SetupLogging=yes
[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked
[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{userprograms}\Meridian Preview\Meridian"; Filename: "{app}\meridian.exe"; IconFilename: "{app}\meridian.ico"
Name: "{userprograms}\Meridian Preview\Uninstall Meridian"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Meridian Preview"; Filename: "{app}\meridian.exe"; IconFilename: "{app}\meridian.ico"; Tasks: desktopicon
