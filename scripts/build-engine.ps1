param(
    [string]$Msys2Root = $env:MSYS2_ROOT,
    [string]$Output = "dpi_simple.exe"
)

$ErrorActionPreference = "Stop"

if (-not $Msys2Root) {
    $Msys2Root = "C:\msys64"
}

$gpp = Join-Path $Msys2Root "mingw64\bin\g++.exe"
if (-not (Test-Path $gpp)) {
    throw "g++ not found at $gpp. Install MSYS2 and the mingw-w64-x86_64-gcc package, or pass -Msys2Root."
}

$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root "engine"
$env:PATH = "$(Split-Path $gpp);$env:PATH"

Push-Location $engine
try {
    & $gpp -std=c++17 -O2 -static -static-libgcc -static-libstdc++ `
        -I include `
        -o $Output `
        src/main_working.cpp `
        src/pcap_reader.cpp `
        src/packet_parser.cpp `
        src/sni_extractor.cpp `
        src/types.cpp `
        -pthread
    if ($LASTEXITCODE -ne 0) {
        throw "Engine build failed with exit code $LASTEXITCODE"
    }
    Write-Output "Built $engine\$Output"
}
finally {
    Pop-Location
}
