<#
.SYNOPSIS
Runs the first-run setup flow for the supported remote capture path.

.DESCRIPTION
This helper wraps `videopipeline.py setup-remote` and auto-installs the
supported Windows dependencies when they are missing.

.EXAMPLE
.\setup_remote.ps1

.EXAMPLE
.\setup_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -SmokeTest

.EXAMPLE
.\setup_remote.ps1 -InstallMode bundle -InstallProfile appliance

.EXAMPLE
.\setup_remote.ps1 -SkipInstallDeps -Host pi@raspberrypi -Interface wlan0
#>

[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [ValidateRange(1, 86400)]
    [int]$Duration = 60,
    [string]$Config = "",
    [string]$Identity = "",
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$Dest = "",
    [ValidateSet("auto", "native", "bundle")]
    [string]$InstallMode = "",
    [ValidateSet("standard", "appliance")]
    [string]$InstallProfile = "",
    [ValidateRange(1, 65535)]
    [int]$HealthPort = 8741,
    [switch]$SmokeTest,
    [switch]$InstallDeps,
    [switch]$SkipInstallDeps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $RepoRoot "scripts\common.ps1")

Ensure-RepoInstallDeps -RepoRoot $RepoRoot -InstallDeps:$InstallDeps -SkipInstallDeps:$SkipInstallDeps

$argsList = [System.Collections.Generic.List[string]]::new()
$argsList.Add("setup-remote")
Add-ArgumentPair -List $argsList -Name "--host" -Value $RemoteHost
Add-ArgumentPair -List $argsList -Name "--interface" -Value $Interface
Add-ArgumentPair -List $argsList -Name "--identity" -Value $Identity
Add-ArgumentPair -List $argsList -Name "--dest" -Value $Dest
Add-ArgumentPair -List $argsList -Name "--install-mode" -Value $InstallMode
Add-ArgumentPair -List $argsList -Name "--install-profile" -Value $InstallProfile
$argsList.Add("--port")
$argsList.Add([string]$Port)
$argsList.Add("--duration")
$argsList.Add([string]$Duration)
if ($InstallProfile) {
    $argsList.Add("--health-port")
    $argsList.Add([string]$HealthPort)
}
if ($SmokeTest) {
    $argsList.Add("--smoke-test")
}

Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $argsList.ToArray()
