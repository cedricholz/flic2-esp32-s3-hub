# reset_build.ps1
# Run from "ESP-IDF PowerShell" so idf.py is on PATH

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Optional: remove sdkconfig files
Get-ChildItem -ErrorAction SilentlyContinue sdkconfig | Remove-Item -Force -ErrorAction SilentlyContinue

# Clean and rebuild for esp32s3
idf.py fullclean
idf.py set-target esp32s3    # implicitly reconfigures
# idf.py reconfigure         # optional; set-target already triggers it
idf.py build