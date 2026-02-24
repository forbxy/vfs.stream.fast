# Config Paths
$KodiAddonsPath_UWP = "$env:LOCALAPPDATA\Packages\XBMCFoundation.Kodi_4n2hpmxwrvr6p\LocalCache\Roaming\Kodi\addons"
$KodiAddonsPath_Exe = "$env:APPDATA\Kodi\addons"

if (Test-Path $KodiAddonsPath_Exe) {
    $KodiAddonsPath = $KodiAddonsPath_Exe
    Write-Host "Detected standard Kodi installation at: $KodiAddonsPath"
} elseif (Test-Path $KodiAddonsPath_UWP) {
    $KodiAddonsPath = $KodiAddonsPath_UWP
    Write-Host "Detected UWP Kodi installation at: $KodiAddonsPath"
} else {
    Write-Error "Kodi addons folder not found. Checked:`n  $KodiAddonsPath_Exe`n  $KodiAddonsPath_UWP"
    exit 1
}

$AddonId = "vfs.stream.fast"
$TargetDir = Join-Path $KodiAddonsPath $AddonId
$ReleaseDll = "build\Release\vfs.stream.fast.dll"
$DebugDll = "build\Debug\vfs.stream.fast.dll"
$RootBuildDll = "build\vfs.stream.fast.dll"

# Check all possible build locations and pick the newest one
$Candidates = @($ReleaseDll, $DebugDll, $RootBuildDll)
$SourceDll = $null
$NewestTime = [DateTime]::MinValue

foreach ($Candidate in $Candidates) {
    if (Test-Path $Candidate) {
        $Time = (Get-Item $Candidate).LastWriteTime
        if ($Time -gt $NewestTime) {
            $NewestTime = $Time
            $SourceDll = $Candidate
        }
    }
}

if ($SourceDll) {
    Write-Host "Selected build: $SourceDll (Time: $NewestTime)"
} else {
    # Default fallback for error message
    $SourceDll = $ReleaseDll
}
$SourceXml = "addon.xml"
$SourceResources = "resources"

# Check Kodi Path is handled at the beginning

# Check Source Files
if (-not (Test-Path $SourceDll)) {
    Write-Error "DLL not found: $SourceDll. Please build the project (F7) first."
    exit 1
}

# Create or Clean Target Directory
if (-not (Test-Path $TargetDir)) {
    Write-Host "Creating addon directory: $TargetDir"
    New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
} else {
    Write-Host "Updating existing addon at: $TargetDir"
}

# Copy Files
try {
    Copy-Item -Path $SourceXml -Destination $TargetDir -Force
    Write-Host "Copied addon.xml"

    if (Test-Path $SourceResources) {
        Copy-Item -Path $SourceResources -Destination $TargetDir -Recurse -Force
        Write-Host "Copied resources folder"
    }

    Copy-Item -Path $SourceDll -Destination $TargetDir -Force
    Write-Host "Copied vfs.stream.fast.dll"
    
    Write-Host "`n[SUCCESS] Addon installed/updated successfully!"
    Write-Host "Please restart Kodi. If Kodi is running, close it to unlock the DLL."
} catch {
    Write-Error "Failed to copy files. If Kodi is running, CLOSE IT and try again."
    Write-Error $_
}