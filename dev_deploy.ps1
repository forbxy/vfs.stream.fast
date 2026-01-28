# Config Paths
$KodiAddonsPath = "$env:LOCALAPPDATA\Packages\XBMCFoundation.Kodi_4n2hpmxwrvr6p\LocalCache\Roaming\Kodi\addons"
$AddonId = "vfs.stream.fast"
$TargetDir = Join-Path $KodiAddonsPath $AddonId
$ReleaseDll = "build\Release\vfs.stream.fast.dll"
$DebugDll = "build\Debug\vfs.stream.fast.dll"
$SourceDll = $null

if ((Test-Path $ReleaseDll) -and (Test-Path $DebugDll)) {
    # Both exist, pick the newer one
    $RelTime = (Get-Item $ReleaseDll).LastWriteTime
    $DebTime = (Get-Item $DebugDll).LastWriteTime
    if ($RelTime -gt $DebTime) {
        $SourceDll = $ReleaseDll
        Write-Host "Selected Release build (Newer)"
    } else {
        $SourceDll = $DebugDll
        Write-Host "Selected Debug build (Newer)"
    }
} elseif (Test-Path $ReleaseDll) {
    $SourceDll = $ReleaseDll
} elseif (Test-Path $DebugDll) {
    $SourceDll = $DebugDll
} else {
    # Neither exists, default to Release for error message purposes, or handle later
    $SourceDll = $ReleaseDll
}
$SourceXml = "addon.xml"
$SourceResources = "resources"

# Check Kodi Path
if (-not (Test-Path $KodiAddonsPath)) {
    Write-Error "Kodi addons folder not found: $KodiAddonsPath. Please check if Kodi (Store Version) is installed."
    exit 1
}

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