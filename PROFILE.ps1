function hola { Write-Host "que pasa" }
function wuup { winget update && winget upgrade --all }
# Otras funciones, aliases, variables de entorno, modificaciones del $env:PATH, etc.
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\catppuccin.omp.json" | Invoke-Expression

