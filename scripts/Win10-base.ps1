###### (funciones)
function reloadPath {
  $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","MACHINE") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","USER")
}

###### actualizar paquetes
winget update
winget upgrade --all

###### instalar paquetes básicos
winget install microsoft.powershell
winget install microsoft.windowsterminal
winget install jandedobbeleer.ohmyposh devcom.jetbrainsmononerdfont
winget install microsoft.visualstudiocode --override '/SILENT /mergetasks="!runcode,addcontextmenufiles,addcontextmenufolders"'
winget install Microsoft.VCRedist.2015+.x64
winget install brave.brave
winget install git.git

reloadPath

###### config powershell (repo)
git clone https://github.com/pabloqpacin/setesur-win "$env:HOMEPATH\setewin"

if (-not (Test-Path -Path $env:HOMEPATH\Documents\PowerShell -PathType Container)) {
    New-Item -Path $env:HOMEPATH\Documents\PowerShell -ItemType Directory }
New-Item -ItemType SymbolicLink -Target "$env:HOMEPATH\setewin\PROFILE.ps1" -Path "$env:HOMEPATH\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"


###### más instalaciones
winget install tldr nmap wireshark neovim.neovim
winget install anydesk audacity.audacity videolan.vlc
winget install 7zip.7zip mobaxterm cpuid.cpu-z realix.hwinfo
winget install jftuga.less sharkdp.bat clement.bottom `
               eza-community.eza fzf gokcehan.lf 'ripgrep gnu'
winget install 'Sysinternals Suite' --accept-package-agreements
winget install Microsoft.Powertoys

reloadPath
tldr --update

###### ~~nerdfont~~

