# Windows 10 Setup con WinGet

- [Windows 10 Setup con WinGet](#windows-10-setup-con-winget)
  - [1. Instalación de Windows 10](#1-instalación-de-windows-10)
  - [2. Actualizar el sistema y la Microsoft Store](#2-actualizar-el-sistema-y-la-microsoft-store)
  - [3. Instalar aplicaciones básicas con WinGet y PowerShell](#3-instalar-aplicaciones-básicas-con-winget-y-powershell)
    - [3.1 WinGet](#31-winget)
    - [3.2 Aplicaciones básicas: Terminal, PowerShell7 \& VSCode](#32-aplicaciones-básicas-terminal-powershell7--vscode)
  - [4. Breve configuración de herramientas básicas](#4-breve-configuración-de-herramientas-básicas)
    - [4.1 Terminal](#41-terminal)
    - [4.2 PowerShell 7](#42-powershell-7)
    - [4.3 ~~VSCode~~](#43-vscode)
  - [5. Instalación de aplicaciones con WinGet \& PowerShell](#5-instalación-de-aplicaciones-con-winget--powershell)
  - [6. ~~Habilitar SSH~~](#6-habilitar-ssh)
  - [7. ~~Contener spyware de Microsoft~~](#7-contener-spyware-de-microsoft)
- [Scripts en repo](#scripts-en-repo)


## 1. Instalación de Windows 10

- Windows 10 Pro
    - Recomiendo separar los datos del sistema y los datos del usuario en dos particiones (`C:` y `D:`)
    - Cuenta Microsoft Online NO: Cuenta Local `no@thankyou.com`
    - ...

<!-- ![img](img?) -->

## 2. Actualizar el sistema y la Microsoft Store

1. Ir a Ajustes, a Windows Update y **descargar e instalar** todas las actualizaciones disponibles.
2. Abrir la tienda de Microsoft (MS Store) y actualizar todo. Es importante que **'Instalador de aplicación'** esté actualizado a la última versión, ya que WinGet depende de esa aplicación para descargar otras aplicaciones de la MS Store.

<!-- ![img](img1) -->

<!-- ![img](img2) -->
<!-- ![img](img3) -->


## 3. Instalar aplicaciones básicas con WinGet y PowerShell

- Abrimos el PowerShell que viene por defecto: Windows PowerShell 5

```ps1
# Mirar info de PowerShell
$PSVersionTable
```

### 3.1 WinGet

- Nos familiarizamos con [WinGet](https://learn.microsoft.com/es-es/windows/package-manager/winget/) y actualizamos las aplicaciones instaladas.
  - Si aparece el mensaje *El origen 'msstore' requiere que acepte los términos del contrato Terms of Transaction*, le decimos `y`

```bash
# Vemos comandos disponibles
winget

# Encontrar ayuda
winget <comando> --help
```
```ps1
# Información de interés ('Raíz de paquete portátil') de cara al $env:PATH...
winget --info

# Vemos las aplicaciones instaladas
winget list

# # Opcionalmente desinstalamos morralla
# winget uninstall <'nombre-aplicacion'>
```
```ps1
# Comprobamos si hay actualizaciones disponibles
winget update

# Actualizamos las aplicaciones instaladas
winget upgrade --all
```
- Si tuviéramos problemas, podemos cambiar la configuración de winget con `winget settings` en el bloc de notas. Yo podría recomendar esta aunque si no hace falta, quizá mejor no tocar.

```jsonc
{
  // "source": { "autoUpdateIntervalInMinutes": 5 },
  "telemetry": { "disable": true },
  "network": { "downloader": "wininet" },
  "visual": { "progressBar": "rainbow" }
}
```

### 3.2 Aplicaciones básicas: Terminal, PowerShell7 & VSCode

- Instalamos:
  - [PowerShell 7](https://github.com/PowerShell/PowerShell) + [OhMyPosh](https://ohmyposh.dev/docs/themes)
  - [Windows Terminal](https://github.com/microsoft/terminal)
  - [VSCode](https://code.visualstudio.com/) para editar archivos de texto y de configuración

```ps1
winget install --help
winget install microsoft.powershell
winget install microsoft.windowsterminal
winget install JanDeDobbeleer.OhMyPosh devcom.JetBrainsMonoNerdFont

winget install Microsoft.VisualStudioCode --override '/SILENT /mergetasks="!addcontextmenufiles,addcontextmenufolders"'
```

## 4. Breve configuración de herramientas básicas

### 4.1 Terminal

- Atajos de teclado

```json
// https://learn.microsoft.com/en-us/windows/terminal/customize-settings/actions#split-a-pane
{ "command": { "action": "splitPane", "split": "horizontal" }, "keys": "alt+shift+-" },
{ "command": { "action": "splitPane", "split": "vertical" }, "keys": "alt+shift+plus" },
```

- Perfil para PowerShell 7

```json
{
    "font": { "size": 10.0, "face": "JetBrainsMono Nerd Font" },
    "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
    "source": "Windows.Terminal.PowershellCore",
    "name": "PowerShell",
    "hidden": false,
    "opacity": 80
}
```

### 4.2 PowerShell 7

- Miramos la info de PowerShell 7

```ps1
$PSVersionTable

# Consultar ruta para el archivo de configuración $PROFILE que queremos mantener
$PROFILE
```
- Creamos nuestro `$PROFILE`: archivo de configuración principal ([documentación oficial](https://learn.microsoft.com/es-es/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4#the-profile-variable)) al estilo `~/.bashrc`
  - *NOTA 1*: como referencia, en mi repo **dotfiles/windows/.** tengo [mi $PROFILE](https://github.com/pabloqpacin/dotfiles/blob/main/windows/Microsoft.PowerShell_profile.ps1), algunos scripts y algo de documentación (en **dotfiles/docs/windows/.**)
  - *NOTA 2*: para que OhMyPosh se vea bien, habrá que asignarle una fuente NerdFont al perfil de PowerShell 7 en WindowsTerminal. Más abajo hay 3 formas de instalar nerdfonts mediante PowerShell.
  - *NOTA 3*: de cara a futuro, sugiero tener nuestro `$PROFILE` en la nube tipo en un repositorio, clonarlo/descargarlo localmente y meter un symlink o similar. Es fácil pero no lo cubro en este documento.

```ps1
# # Podemos crear las carpetas y los archivos manualmente...
# New-Item -Path "$env:HOMEPATH\Documents\PowerShell" -ItemType Directory
# New-Item $PROFILE

# ... pero así, al guardar se crean también de una los directorios necesarios para la variable $PROFILE
nvim $PROFILE || code $PROFILE
```
```ps1
# Este es un contenido de prueba para el archivo $PROFILE que estamos editando

function hola { Write-Host "que pasa" }
function wuup { winget update && winget upgrade --all }
# Otras funciones, aliases, variables de entorno, modificaciones del $env:PATH, etc.
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\catppuccin.omp.json" | Invoke-Expression
```
```ps1
# De vuelta en la terminal cargamos de nuevo el $PROFILE
.$PROFILE
hola
```

- Algunos comandos últiles

```ps1
# Definición de funciones y comandos
(Get-Command hola).Definition

# Info de almacenamiento
Get-PSDrive || Get-Volume
```

### 4.3 ~~VSCode~~

- Extensiones

```ps1
# ...
```
- Ajustes

```json
// ...
```

## 5. Instalación de aplicaciones con WinGet & PowerShell

- Navegador web

```ps1
winget install brave.brave google.chrome          # recomiendo la extensión 'Dark Reader'
```

- Herramientas habituales

```ps1
winget install anydesk audacity.audacity videolan.vlc
```

- Otras herramientas recomendadas

```ps1
winget install 7zip.7zip mobaxterm `
               cpuid.cpu-z realix.hwinfo

winget install Microsoft.VCRedist.2015+.x64 `
               wireshark git.git nmap tldr

tldr --update
tldr tldr
tldr new-item && tldr get-command

winget install 'Sysinternals Suite' --accept-package-agreements
winget install Microsoft.Powertoys
  # tweak 'Run at startup' -- see 'TaskScheduler'/logon

# winget install docker.dockerdesktop                       # depende de WSL...
# winget install keepassxcteam.keepassxc                    # gestor de contraseñas local (no cloud)

shutdown /r
```

- Herramientas de pura terminal

```ps1
winget install jftuga.less sharkdp.bat clement.bottom 
               eza-community.eza fzf gokcehan.lf 'ripgrep gnu'

winget install neovim.neovim
```

<details>
<summary>NerdFonts</summary>

- Instalación de NerdFont via script (Opción 1)

```ps1
# Script variables
# $pkg = "FiraCode"
$pkg = "CascadiaCode"
$pkgURL = "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.0.2/$pkg"
$helperURL = "https://raw.githubusercontent.com/pabloqpacin/PowerShell_Scripts/master/InstallFonts.ps1"

# Download 'FiraCode Nerd Font'
Invoke-WebRequest -Uri $pkgURL -OutFile $env:TEMP\$pkg.zip

# Extract zip
Expand-Archive -Path $env:TEMP\$pkg.zip -DestinationPath $env:TEMP\$pkg

# Install font faces
curl $helperURL --output "$env:TEMP\$pkg\helper.ps1"
Set-Location $env:TEMP; .\$pkg\helper.ps1
Set-Location -

# [PDQ Deploy](https://www.pdq.com/blog/how-to-download-and-install-fonts)
```

- Instalación de NerdFont via script (Opción 2)

```ps1
$exists = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' | Select-String FiraCode)

if (-not ($exists)) {

    $helper = "https://raw.githubusercontent.com/pabloqpacin/PowerShell_Scripts/master/InstallFonts.ps1"

    Write-Host '== Downloading Nerdfont FiraCode =='
    Invoke-WebRequest -Uri https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/FiraCode.zip -OutFile FiraCode.zip
    Expand-Archive -Path FiraCode.zip -DestinationPath FiraCode

    Set-Location FiraCode
    Invoke-WebRequest -Uri $helper -OutFile helper.ps1
    Write-Host '== Installing Nerdfont FiraCode =='
    .\helper.ps1

    Set-Location ..
    Remove-Item FiraCode.zip
    Remove-Item FiraCode -r

} else {
    Write-Host '== Nerdfont FiraCode is already installed =='
}
```

- Opción 3, ya mencionada más arriba

```ps1
winget install devcom.JetBrainsMonoNerdFont
```

</details>

<details>
<summary>Más movidas</summary>

## 6. ~~Habilitar SSH~~

- Script siguiendo la [documentación oficial](https://learn.microsoft.com/es-es/windows-server/administration/openssh/openssh_install_firstuse?tabs=gui)

```ps1
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0


# Start the sshd service
Start-Service sshd

# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
```

## 7. ~~Contener spyware de Microsoft~~

- Editar el archivo **hosts** (como Administradores) en `C:\Windows\System32\drivers\etc\hosts`
  - [@The PC Security Channel: Stop Windows Spying with hosts file](https://www.youtube.com/watch?v=IJr2DcffquI)
  - NOTA: también se puede hacer mediante **PowerToys**


```ps1
nodepad $env:SystemRoot\System32\drivers\etc\hosts
nvim $env:SystemRoot\System32\drivers\etc\hosts
code $env:SystemRoot\System32\drivers\etc\hosts
```
```hosts
127.0.0.1       localhost
::1             localhost
127.0.0.1       data.microsoft.com
127.0.0.1       msftconnecttest.com
127.0.0.1       azureedge.net
127.0.0.1       activity.windows.com
127.0.0.1       bingapis.com
127.0.0.1       msedge.net
127.0.0.1       assets.msn.com
127.0.0.1       scorecardresearch.com
127.0.0.1       edge.microsoft.com
```

</details>


---

# Scripts en repo

- NOTA: el symlink del $PROFILE solo puede hacerse si PowerShell se ejecutaba como Administrador para correr el script -- recomiendo abrir PowerShell5 como Administrador directamente

```ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pabloqpacin/setesur-win/main/scripts/Win10-base.ps1" -OutFile "$env:HOMEPATH\setup.ps1"
Set-ExecutionPolicy Unrestricted -Scope Process
cd $env:HOMEPATH
.\setup.ps1
```
