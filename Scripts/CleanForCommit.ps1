$ErrorActionPreference = 'Stop'

# Determine the script folder and move to its parent (repo root)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = Resolve-Path -Path (Join-Path $scriptDir '..') | Select-Object -ExpandProperty Path
Set-Location -Path $repoRoot

Write-Host "Working from repository root: $repoRoot"

# 1) Remove Reports folder if it exists
$reportsPath = Join-Path $repoRoot 'Reports'
if (Test-Path -LiteralPath $reportsPath) {
    Write-Host "Removing Reports folder: $reportsPath"
    Remove-Item -LiteralPath $reportsPath -Recurse -Force
} else {
    Write-Host "No Reports folder found at: $reportsPath"
}

# 2) Update ResultCount to 0 in resources/*.json (non-recursive)
$resourcesPath = Join-Path $repoRoot 'resources'
if (-not (Test-Path -LiteralPath $resourcesPath)) {
    Write-Host "No resources folder found at: $resourcesPath"
    exit 0
}

$jsonFiles = Get-ChildItem -Path $resourcesPath -Filter '*.json' -File -ErrorAction SilentlyContinue
if (-not $jsonFiles) {
    Write-Host "No JSON files found in $resourcesPath"
    exit 0
}

foreach ($file in $jsonFiles) {
    try {
        Write-Host "Processing $($file.Name)..."

        $raw = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop

        # Replace numeric ResultCount values with 0 (handles whitespace, negative numbers)
        $updated = $raw -replace '("ResultCount"\s*:\s*)(-?\d+)', '${1}0'

        if ($updated -ne $raw) {
            # Write UTF8 without BOM
            $updated | Out-File -FilePath $file.FullName -Encoding utf8 -Force
            Write-Host "Updated $($file.Name) (ResultCount -> 0)"
        } else {
            Write-Host "No ResultCount changes needed in $($file.Name)"
        }
    } catch {
        Write-Warning "Failed to process $($file.FullName): $($_.Exception.Message)"
    }
}

Write-Host "CleanForCommit completed."