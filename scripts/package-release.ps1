#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Tag,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Native {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

$root = Split-Path -Parent $PSScriptRoot
$originalLocation = Get-Location
$originalTargetDirectory = $env:CARGO_TARGET_DIR
try {
    Set-Location -LiteralPath $root
    $dirty = @(Invoke-Native git @('status', '--porcelain', '--untracked-files=normal'))
    if ($dirty.Count -ne 0) {
        throw 'Release packaging requires a clean, committed worktree.'
    }
    $commit = (Invoke-Native git @('rev-parse', 'HEAD')).Trim()
    $tagCommit = (Invoke-Native git @('rev-parse', '--verify', "$Tag^{commit}")).Trim()
    if ($tagCommit -ne $commit) {
        throw "Tag $Tag does not point to the checked-out commit."
    }
    $metadata = Invoke-Native cargo @('metadata', '--locked', '--offline', '--no-deps', '--format-version', '1') |
        ConvertFrom-Json
    $cli = @($metadata.packages | Where-Object name -EQ 'servicemanager-cli')
    if ($cli.Count -ne 1 -or "v$($cli[0].version)" -ne $Tag) {
        throw 'Release tag and CLI package version must match.'
    }
    $version = $cli[0].version
    $changelog = Get-Content -LiteralPath (Join-Path $root 'CHANGELOG.md') -Raw
    $entry = [regex]::Match($changelog, "(?ms)^## \[$([regex]::Escape($Tag))\][^\r\n]*\r?\n(.*?)(?=^## |\z)")
    if (-not $entry.Success) {
        throw "CHANGELOG.md has no release entry for $Tag."
    }

    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path $root 'target\dist'
    }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $OutputDirectory) {
        throw "Output directory already exists: $OutputDirectory. Choose a fresh directory."
    }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $staging = Join-Path $OutputDirectory '.staging'
    $sourceName = "ngsm-$Tag-source"
    $sourceRoot = Join-Path $staging $sourceName
    New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null
    $trackedArchive = Join-Path $staging 'tracked-source.tar'
    Invoke-Native git @('archive', '--format=tar', "--output=$trackedArchive", 'HEAD')
    Invoke-Native tar @('-xf', $trackedArchive, '-C', $sourceRoot)

    Set-Location -LiteralPath $sourceRoot
    $vendorConfig = @(Invoke-Native cargo @('vendor', '--locked', '--versioned-dirs', 'vendor'))
    if ($vendorConfig.Count -eq 0) {
        throw 'cargo vendor did not produce a source replacement configuration.'
    }
    $cargoConfig = Join-Path $sourceRoot '.cargo\config.toml'
    [IO.File]::AppendAllText($cargoConfig, "`n" + ($vendorConfig -join "`n") + "`n")

    # Build the exact bundled sources without the registry or network. Keep build
    # output outside the source archive and retain the workspace's static CRT flags.
    $env:CARGO_TARGET_DIR = Join-Path $root 'target'
    $target = 'x86_64-pc-windows-msvc'
    $resolved = Invoke-Native cargo @('metadata', '--frozen', '--format-version', '1') | ConvertFrom-Json
    Invoke-Native cargo @('build', '--frozen', '--release', '--target', $target, '-p', 'servicemanager-cli')
    $binary = Join-Path $env:CARGO_TARGET_DIR "$target\release\ngsm.exe"
    $identity = (Get-Item -LiteralPath $binary).VersionInfo
    if ($identity.FileVersion -ne $version -or $identity.ProductVersion -ne $version -or
        $identity.OriginalFilename -ne 'ngsm.exe') {
        throw 'Built executable identity does not match the release version.'
    }
    $reportedVersion = (Invoke-Native $binary @('--version')).Trim()
    if ($reportedVersion -ne "ngsm $version") {
        throw "Unexpected CLI version: $reportedVersion"
    }
    Invoke-Native $binary @('--help') | Out-Null
    $services = Invoke-Native $binary @('--json', 'list') | ConvertFrom-Json -NoEnumerate
    if ($null -eq $services -or $null -eq $services.PSObject.Properties['services'] -or
        $services.services -isnot [array]) {
        throw 'The release executable did not return a JSON service list.'
    }

    Copy-Item -LiteralPath $binary -Destination (Join-Path $OutputDirectory 'ngsm.exe')
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'LICENSE') -Destination (Join-Path $OutputDirectory 'LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'THIRD-PARTY-NOTICES.md') -Destination $OutputDirectory
    $slint = @($resolved.packages | Where-Object name -EQ 'slint')
    if ($slint.Count -ne 1) {
        throw 'The source bundle must contain exactly one Slint runtime package.'
    }
    $gpl = Join-Path (Split-Path -Parent $slint[0].manifest_path) 'LICENSES\GPL-3.0-only.txt'
    Copy-Item -LiteralPath $gpl -Destination (Join-Path $OutputDirectory 'GPL-3.0.txt')

    $dependencyLines = @(
        "NGSM $Tag - resolved Cargo packages"
        'Includes build-time and platform-specific packages, not only libraries linked into ngsm.exe.'
        'The exact package sources and license files are in the accompanying source archive (vendor directory).'
        'Slint is used under GPL-3.0-only; NGSM-authored sources remain 0BSD.'
        ''
        'Package | Version | License expression | Repository'
    )
    $dependencyLines += $resolved.packages | Sort-Object name, version | ForEach-Object {
        $license = if ($_.license) { $_.license } else { 'See package license file in source archive' }
        "$($_.name) | $($_.version) | $license | $($_.repository)"
    }
    [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'DEPENDENCIES.txt'), [string[]]$dependencyLines)

    $workflowUrl = if ($env:GITHUB_ACTIONS -eq 'true') {
        "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
    } else {
        $null
    }
    $buildInfo = [ordered]@{
        version = $version
        tag = $Tag
        commit = $commit
        repository = $cli[0].repository
        target = $target
        features = 'default (GUI, CLI, service runner; no broker)'
        source_archive = "$sourceName.tar.gz"
        build_command = "cargo build --frozen --release --target $target -p servicemanager-cli"
        rustc = @(Invoke-Native rustc @('-vV'))
        cargo = Invoke-Native cargo @('--version')
        workflow = $workflowUrl
        authenticode_signed = $false
    }
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'BUILD-INFO.json'), ($buildInfo | ConvertTo-Json -Depth 4) + "`n")

    Set-Location -LiteralPath $root
    Invoke-Native tar @('-czf', (Join-Path $OutputDirectory "$sourceName.tar.gz"), '-C', $staging, $sourceName)
    $assetNames = @(
        'ngsm.exe', "$sourceName.tar.gz", 'BUILD-INFO.json', 'DEPENDENCIES.txt',
        'THIRD-PARTY-NOTICES.md', 'LICENSE.txt', 'GPL-3.0.txt'
    )
    $checksums = foreach ($name in $assetNames) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'SHA256SUMS.txt'), [string[]]$checksums)
    $notes = @"
NGSM **$Tag** - Windows x64, one executable with the GUI, CLI, and service runner.

$($entry.Groups[1].Value.Trim())

### Downloads and provenance

- Download ``ngsm.exe`` and place it in an administrator-protected directory such as ``C:\Program Files\NGSM``. The binary is unsigned.
- ``SHA256SUMS.txt`` contains SHA-256 hashes for all payload assets.
- ``$sourceName.tar.gz`` contains the exact tagged source and vendored dependency sources/licenses. The executable was built from this bundle with Cargo's network access disabled.
- ``BUILD-INFO.json`` records commit ``$commit``, toolchain, target, and the build run when available.
- See ``THIRD-PARTY-NOTICES.md``, ``DEPENDENCIES.txt``, ``LICENSE.txt``, and ``GPL-3.0.txt`` for licensing details.
"@
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'RELEASE-NOTES.md'), $notes + "`n")
    Remove-Item -LiteralPath $staging -Recurse -Force
    Write-Host "Prepared $Tag release assets in $OutputDirectory"
} finally {
    $env:CARGO_TARGET_DIR = $originalTargetDirectory
    Set-Location -LiteralPath $originalLocation
}
