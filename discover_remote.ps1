<#
.SYNOPSIS
Discovers appliance-style remote capture nodes on the local network.

.DESCRIPTION
This helper wraps `videopipeline.py discover-remote`, auto-installs the
supported Windows dependencies when they are missing, and can optionally save
the selected Raspberry Pi or Ubuntu appliance into the active config file.

.EXAMPLE
.\discover_remote.ps1

.EXAMPLE
.\discover_remote.ps1 -Save

.EXAMPLE
.\discover_remote.ps1 -Network 192.168.1.0/24 -HealthPort 9001 -Save -Select 1
#>

[CmdletBinding()]
param(
    [string[]]$Network = @(),
    [ValidateRange(1, 65535)]
    [int]$HealthPort = 8741,
    [ValidateScript({ $_ -gt 0 -and $_ -le 30 })]
    [double]$Timeout = 0.35,
    [ValidateRange(1, 4096)]
    [int]$MaxHosts = 64,
    [string]$Config = "",
    [switch]$Save,
    [ValidateRange(1, 512)]
    [int]$Select = 0,
    [switch]$InstallDeps,
    [switch]$SkipInstallDeps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $RepoRoot "scripts\common.ps1")

Ensure-RepoInstallDeps -RepoRoot $RepoRoot -InstallDeps:$InstallDeps -SkipInstallDeps:$SkipInstallDeps

$argsList = [System.Collections.Generic.List[string]]::new()
$argsList.Add("discover-remote")
foreach ($item in $Network) {
    Add-ArgumentPair -List $argsList -Name "--network" -Value $item
}
$argsList.Add("--health-port")
$argsList.Add([string]$HealthPort)
$argsList.Add("--timeout")
$argsList.Add([string]$Timeout)
$argsList.Add("--max-hosts")
$argsList.Add([string]$MaxHosts)
if ($Save) {
    $argsList.Add("--save")
}
if ($Select -gt 0) {
    $argsList.Add("--select")
    $argsList.Add([string]$Select)
}

$pythonExe = Resolve-RepoPythonExe -RepoRoot $RepoRoot
$scriptPath = Join-Path $RepoRoot "videopipeline.py"
$commandArgs = [System.Collections.Generic.List[string]]::new()
if ($Config) {
    $commandArgs.Add("--config")
    $commandArgs.Add($Config)
}
foreach ($item in $argsList) {
    $commandArgs.Add($item)
}

$displayArgs = $commandArgs | ForEach-Object { Format-DisplayArgument -Value $_ }
Write-Host ""
Write-Host ("> {0} {1} {2}" -f (Format-DisplayArgument -Value $pythonExe), (Format-DisplayArgument -Value $scriptPath), ($displayArgs -join " "))

& $pythonExe $scriptPath @commandArgs
exit $LASTEXITCODE
