[CmdletBinding()]
param(
    [ValidateSet("Check", "Build", "Run")]
    [string]$Mode = "Build",
    [switch]$SkipGStreamerCheck
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ManifestPath = Join-Path $RepoRoot "apps\desktop\Cargo.toml"
$ExecutablePath = Join-Path $RepoRoot "apps\desktop\target\release\remote-desktop.exe"

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "缺少命令 $Name。请安装 Rust stable 和 Visual Studio 2022 C++ Build Tools。"
    }
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath 执行失败，退出码 $LASTEXITCODE"
    }
}

function Add-GStreamerToPath {
    $Candidates = @()
    if ($env:GSTREAMER_1_0_ROOT_MSVC_X86_64) {
        $Candidates += (Join-Path $env:GSTREAMER_1_0_ROOT_MSVC_X86_64 "bin")
    }
    if ($env:ProgramFiles) {
        $Candidates += (Join-Path $env:ProgramFiles "gstreamer\1.0\msvc_x86_64\bin")
    }
    $Candidates += "C:\gstreamer\1.0\msvc_x86_64\bin"

    foreach ($Candidate in $Candidates | Select-Object -Unique) {
        if (Test-Path (Join-Path $Candidate "gst-launch-1.0.exe")) {
            $env:Path = "$Candidate;$env:Path"
            return
        }
    }

    if (-not (Get-Command "gst-launch-1.0.exe" -ErrorAction SilentlyContinue)) {
        throw "未找到 GStreamer MSVC x86_64 full runtime。"
    }
}

function Test-GStreamer {
    Add-GStreamerToPath
    foreach ($Plugin in @("rawvideoparse", "videoconvert", "x264enc", "multipartmux", "fdsink")) {
        Invoke-Native "gst-inspect-1.0.exe" $Plugin
    }
}

function Test-ReleaseConfiguration {
    foreach ($Name in @(
        "RCTL_OFFICIAL_API_URL",
        "RCTL_OFFICIAL_SIGNAL_URL",
        "RCTL_OFFICIAL_RELAY_URL"
    )) {
        $Value = [Environment]::GetEnvironmentVariable($Name)
        if ([string]::IsNullOrWhiteSpace($Value)) {
            throw "Release 构建缺少环境变量 $Name。"
        }
    }

    if (-not $env:RCTL_OFFICIAL_API_URL.StartsWith("https://")) {
        throw "RCTL_OFFICIAL_API_URL 必须使用 https。"
    }
    if (-not $env:RCTL_OFFICIAL_SIGNAL_URL.StartsWith("wss://")) {
        throw "RCTL_OFFICIAL_SIGNAL_URL 必须使用 wss。"
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "此脚本必须在 Windows 10/11 或 Windows CI runner 上执行。"
}

Assert-Command "cargo.exe"
Assert-Command "rustup.exe"
Invoke-Native "rustup.exe" "target" "add" "x86_64-pc-windows-msvc"

if (-not $SkipGStreamerCheck) {
    Test-GStreamer
}

Push-Location $RepoRoot
try {
    $TestArguments = @(
        "test",
        "--manifest-path", $ManifestPath,
        "--all-targets",
        "--locked"
    )
    Invoke-Native "cargo.exe" @TestArguments

    if ($Mode -eq "Check") {
        Write-Host "Windows tests passed."
        exit 0
    }

    Test-ReleaseConfiguration
    $BuildArguments = @(
        "build",
        "--manifest-path", $ManifestPath,
        "--release",
        "--locked"
    )
    Invoke-Native "cargo.exe" @BuildArguments

    if (-not (Test-Path $ExecutablePath)) {
        throw "构建完成但未找到 $ExecutablePath"
    }
    Write-Host "Windows executable: $ExecutablePath"

    if ($Mode -eq "Run") {
        & $ExecutablePath
        if ($LASTEXITCODE -ne 0) {
            throw "remote-desktop.exe 退出码 $LASTEXITCODE"
        }
    }
}
finally {
    Pop-Location
}
