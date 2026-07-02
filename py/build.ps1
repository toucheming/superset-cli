# Build superset-query.exe -> dist/win/superset-query.exe
$ROOT = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

Write-Host "Python: $((python --version) 2>&1)"

Write-Host "Installing/checking dependencies..."
python -m pip install pyinstaller requests cryptography keyring 2>&1 | ForEach-Object { Write-Host "  $_" }

Write-Host "Building dist/win/superset-query.exe ..."
Set-Location $ROOT

python -c "import PyInstaller; print('PyInstaller OK:', PyInstaller.__version__)"
if (-not $?) { Write-Host "PyInstaller not available after install" -ForegroundColor Red; exit 1 }

python -m PyInstaller --noconfirm `
  --distpath "$ROOT\dist\win" `
  --workpath "$ROOT\build\superset-query" `
  superset-query.spec

if (-not $?) {
    Write-Host "PyInstaller failed" -ForegroundColor Red
    exit 1
}

Write-Host "Done."
