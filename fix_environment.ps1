# PowerShell script to fix iKARMA environment
# Run this to recreate your Python environment

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "iKARMA Environment Fix Script" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Cyan

# Step 1: Deactivate current environment if active
Write-Host "`n[STEP 1] Deactivating current environment..." -ForegroundColor Green
try {
    deactivate
    Write-Host "  [OK] Environment deactivated" -ForegroundColor Green
} catch {
    Write-Host "  [OK] No environment was active" -ForegroundColor Green
}

# Step 2: Remove broken virtual environment
Write-Host "`n[STEP 2] Removing broken virtual environment..." -ForegroundColor Green
if (Test-Path "ikarma-env") {
    Remove-Item -Recurse -Force ikarma-env
    Write-Host "  [OK] Old environment removed" -ForegroundColor Green
} else {
    Write-Host "  [OK] No old environment to remove" -ForegroundColor Green
}

# Step 3: Find Python
Write-Host "`n[STEP 3] Finding Python installation..." -ForegroundColor Green
$pythonCmd = $null

# Try different Python commands
$pythonCandidates = @("python", "py", "python3")
foreach ($cmd in $pythonCandidates) {
    try {
        $version = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pythonCmd = $cmd
            Write-Host "  [OK] Found Python: $cmd" -ForegroundColor Green
            Write-Host "       Version: $version" -ForegroundColor Gray
            break
        }
    } catch {
        continue
    }
}

if (-not $pythonCmd) {
    Write-Host "  [ERROR] Python not found!" -ForegroundColor Red
    Write-Host "  [FIX] Install Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Step 4: Create new virtual environment
Write-Host "`n[STEP 4] Creating new virtual environment..." -ForegroundColor Green
& $pythonCmd -m venv ikarma-env

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Virtual environment created" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to create virtual environment" -ForegroundColor Red
    Write-Host "  [FIX] Try running: $pythonCmd -m pip install --user virtualenv" -ForegroundColor Yellow
    exit 1
}

# Step 5: Activate virtual environment
Write-Host "`n[STEP 5] Activating virtual environment..." -ForegroundColor Green
& .\ikarma-env\Scripts\Activate.ps1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Virtual environment activated" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Could not activate automatically" -ForegroundColor Yellow
    Write-Host "  [FIX] Run manually: .\ikarma-env\Scripts\Activate.ps1" -ForegroundColor Yellow
}

# Step 6: Upgrade pip
Write-Host "`n[STEP 6] Upgrading pip..." -ForegroundColor Green
python -m pip install --upgrade pip --quiet

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] pip upgraded" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] pip upgrade failed (not critical)" -ForegroundColor Yellow
}

# Step 7: Install dependencies
Write-Host "`n[STEP 7] Installing dependencies..." -ForegroundColor Green

$packages = @("capstone", "volatility3", "pefile", "yara-python")

foreach ($package in $packages) {
    Write-Host "  Installing $package..." -ForegroundColor Gray
    python -m pip install $package --quiet

    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] $package installed" -ForegroundColor Green
    } else {
        Write-Host "    [WARNING] $package failed to install" -ForegroundColor Yellow
    }
}

# Step 8: Verify installation
Write-Host "`n[STEP 8] Verifying installation..." -ForegroundColor Green

# Test capstone
Write-Host "  Testing capstone..." -ForegroundColor Gray
$capstonTest = python -c "import capstone; print('[OK] Capstone version:', capstone.__version__)" 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "    $capstonTest" -ForegroundColor Green
} else {
    Write-Host "    [ERROR] Capstone import failed" -ForegroundColor Red
}

# Test core modules
Write-Host "  Testing iKARMA modules..." -ForegroundColor Gray
$moduleTest = python -c "from core.api_patterns import API_DATABASE; from utils.api_scanner import find_dangerous_apis; print('[OK] iKARMA modules loaded')" 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "    $moduleTest" -ForegroundColor Green
} else {
    Write-Host "    [WARNING] iKARMA modules not yet tested (run from project directory)" -ForegroundColor Yellow
}

# Final summary
Write-Host "`n" -NoNewline
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "ENVIRONMENT SETUP COMPLETE!" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Green
Write-Host "  1. Make sure you see (ikarma-env) in your prompt" -ForegroundColor Gray
Write-Host "  2. If not, run: .\ikarma-env\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "  3. Test your scanner: python test_person2_standalone.py test.mem" -ForegroundColor Gray
Write-Host "  4. Run unit tests: python utils\api_scanner.py" -ForegroundColor Gray

Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
Write-Host "  If activation fails, run this manually:" -ForegroundColor Gray
Write-Host "    .\ikarma-env\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "  If that doesn't work, use system Python:" -ForegroundColor Gray
Write-Host "    py -m pip install capstone" -ForegroundColor Gray
Write-Host "    py test_person2_standalone.py test.mem" -ForegroundColor Gray

Write-Host "`n" -NoNewline
