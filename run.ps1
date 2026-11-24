# PowerShell equivalent of the Makefile:  .\run.ps1 pipeline   |   .\run.ps1 lanl -Days 15
param(
    [Parameter(Position = 0)][ValidateSet("setup", "synthetic", "lanl", "ingest", "features", "pipeline", "evaluate", "explain", "test", "clean")]
    [string]$Target = "pipeline",
    [string]$Config = "config/default.toml",
    [int]$Days = 15
)
$ErrorActionPreference = "Stop"
$py = if (Test-Path ".venv/Scripts/python.exe") { ".venv/Scripts/python.exe" } else { "python" }

function Invoke-Py { & $py @args; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }

switch ($Target) {
    "setup"     { Invoke-Py -m pip install -e ".[dev,models]" }
    "synthetic" { Invoke-Py -m threatdet.data.synthetic --config $Config }
    "lanl"      { Invoke-Py -m threatdet.data.download_lanl --config $Config --days $Days }
    "ingest"    { Invoke-Py -m threatdet.pipeline ingest --config $Config }
    "features"  { Invoke-Py -m threatdet.pipeline features --config $Config }
    "pipeline"  { Invoke-Py -m threatdet.data.synthetic --config $Config; Invoke-Py -m threatdet.pipeline all --config $Config }
    "evaluate"  { Invoke-Py -m threatdet.evaluate --config $Config }
    "explain"   { Invoke-Py -m triage.explain --config $Config }
    "test"      { Invoke-Py -m pytest }
    "clean"     { Get-ChildItem data -Filter "*.duckdb*" -ErrorAction SilentlyContinue | Remove-Item -Confirm:$false }
}
