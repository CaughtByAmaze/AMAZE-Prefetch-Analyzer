# AMAZE Prefetch Analyzer v1.4
# Enhanced UI and reporting
# Fixed version numbering

# Clear the console for a clean start
Clear-Host

# Configuration
$Config = @{
    PrefetchPath = "$env:SystemRoot\Prefetch"
    MinTimeTolerance = 30    # Minimum time difference in seconds to flag
    MaxTimeTolerance = 45    # Maximum time difference in seconds to flag
    MaxFileAgeDays = 180     # Maximum age of files to consider
    AnalyzeExecutionCount = $false  # Disabled since it requires actual parsing
}

# UI Functions
function Show-Header {
    param([string]$Title)
    $width = [System.Math]::Min(80, $Host.UI.RawUI.WindowSize.Width - 1)
    $padding = ($width - $Title.Length) / 2
    $padLeft = [math]::Floor($padding)
    $padRight = [math]::Ceiling($padding)

    Write-Host ("=" * $width) -ForegroundColor DarkCyan
    Write-Host (" " * $padLeft + $Title + " " * $padRight) -ForegroundColor White -BackgroundColor DarkRed
    Write-Host ("=" * $width) -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-Section {
    param([string]$Title, [string]$Color = "Yellow")
    Write-Host "=== $Title ===" -ForegroundColor $Color
    Write-Host ""
}

function Show-Progress {
    param([string]$Message, [int]$Percent)
    $barLength = 50
    $completed = [math]::Round($Percent * $barLength / 100)
    $remaining = $barLength - $completed

    Write-Host -NoNewline ("`r$Message [")
    Write-Host -NoNewline ("#" * $completed) -ForegroundColor Green
    Write-Host -NoNewline ("=" * $remaining)
    Write-Host -NoNewline ("] $Percent%")

    if ($Percent -eq 100) {
        Write-Host ""
    }
}

function Show-Finding {
    param([string]$Type, [string]$Message, [string]$Severity = "Medium")

    $colors = @{
        "Critical" = "Red"
        "High"     = "Magenta"
        "Medium"   = "Yellow"
        "Low"      = "Cyan"
        "Info"     = "Gray"
    }

    $symbols = @{
        "Critical" = "X"    # X for critical
        "High"     = "!!"   # Double bang for high
        "Medium"   = "!"    # Single bang for medium
        "Low"      = "i"    # i for low
        "Info"     = "-"    # Hyphen for info
    }

    $color = $colors[$Severity]
    $symbol = $symbols[$Severity]

    Write-Host ("[$symbol] ").PadRight(6) -NoNewline -ForegroundColor $color
    Write-Host "$Type".PadRight(18) -NoNewline -ForegroundColor $color
    Write-Host $Message
}

function Get-FileHashSHA256 {
    param([string]$filePath)
    try {
        $hashObject = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return $hashObject.Hash
    } catch {
        Show-Finding -Type "Hash Error" -Message "Failed to calculate hash for: $filePath" -Severity "Medium"
        return $null
    }
}

function Get-PrefetchMetadata {
    param([string]$FilePath)
    
    try {
        $fileInfo = Get-Item $FilePath
        return @{
            FileName = $fileInfo.Name
            FullPath = $fileInfo.FullName
            SizeKB = [math]::Round($fileInfo.Length / 1KB, 2)
            Created = $fileInfo.CreationTime
            Modified = $fileInfo.LastWriteTime
            Accessed = $fileInfo.LastAccessTime
            Attributes = $fileInfo.Attributes
        }
    } catch {
        Show-Finding -Type "Metadata Error" -Message "Failed to get metadata for: $FilePath" -Severity "Medium"
        return $null
    }
}

try {
    # Display header
    Show-Header -Title "AMAZE Prefetch Analyzer v1.4"
    Write-Host "Version 1.4 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""

    # Check Prefetch directory
    if (-not (Test-Path $Config.PrefetchPath)) {
        Show-Finding -Type "Critical Error" -Message "Prefetch directory not found!" -Severity "Critical"
        Read-Host "Press Enter to exit"
        exit
    }

    # Get prefetch files within age limit
    Show-Progress -Message "Scanning Prefetch directory" -Percent 10
    try {
        $cutoffDate = (Get-Date).AddDays(-$Config.MaxFileAgeDays)
        $PrefetchFiles = Get-ChildItem -Path $Config.PrefetchPath -Filter "*.pf" -ErrorAction Stop | 
                        Where-Object { $_.LastWriteTime -ge $cutoffDate }
    } catch {
        Show-Finding -Type "Scan Error" -Message "Failed to scan directory" -Severity "High"
        Read-Host "Press Enter to exit"
        exit
    }

    if (-not $PrefetchFiles -or $PrefetchFiles.Count -eq 0) {
        Show-Finding -Type "Warning" -Message "No Prefetch files found" -Severity "Medium"
        Read-Host "Press Enter to exit"
        exit
    }

    # Initialize results
    $EmptyFiles = @()
    $ReadOnlyFiles = @()
    $FileHashes = @{}
    $TimeMismatchFiles = @()
    $SuspiciousCount = 0

    # Show file analysis progress header
    Write-Host "--- File Analysis Progress ---" -ForegroundColor Cyan
    Write-Host ""
    
    # Analyze files
    $totalFiles = $PrefetchFiles.Count
    $currentFile = 0

    foreach ($File in $PrefetchFiles) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100)
        Show-Progress -Message "Analyzing file $currentFile of $totalFiles" -Percent $percentComplete

        # Check for empty files
        if ($File.Length -eq 0) {
            $EmptyFiles += $File.Name
            $SuspiciousCount++
            continue
        }

        # Check for read-only files
        if ($File.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $ReadOnlyFiles += $File.Name
            $SuspiciousCount++
        }

        # Calculate hash
        $Hash = Get-FileHashSHA256 -filePath $File.FullName
        if ($Hash) {
            if ($FileHashes.ContainsKey($Hash)) {
                $FileHashes[$Hash] += $File.Name
            } else {
                $FileHashes[$Hash] = @($File.Name)
            }
        }

        # Check time mismatches
        $TimeDifference = $File.LastWriteTime - $File.LastAccessTime
        $AbsDifference = [math]::Abs($TimeDifference.TotalSeconds)

        if ($AbsDifference -ge $Config.MinTimeTolerance -and $AbsDifference -le $Config.MaxTimeTolerance) {
            $TimeMismatchFiles += "$($File.Name) (Last Run: $($File.LastAccessTime), Modified: $($File.LastWriteTime))"
            $SuspiciousCount++
        }
    }

    # Display results
    Clear-Host
    Show-Header -Title "Analysis Results"

    # Summary
    Show-Section -Title "Summary"
    Write-Host "Total Files Analyzed: " -NoNewline -ForegroundColor Cyan
    Write-Host $totalFiles -ForegroundColor White

    Write-Host "Suspicious Findings:  " -NoNewline -ForegroundColor Cyan
    if ($SuspiciousCount -gt 0) {
        Write-Host $SuspiciousCount -ForegroundColor Red
    } else {
        Write-Host $SuspiciousCount -ForegroundColor Green
    }
    Write-Host ""

    # Findings
    if ($EmptyFiles.Count -gt 0) {
        Show-Section -Title "Empty Files Found" -Color "Red"
        $EmptyFiles | ForEach-Object {
            Show-Finding -Type "Empty File" -Message $_ -Severity "Critical"
        }
    }

    if ($ReadOnlyFiles.Count -gt 0) {
        Show-Section -Title "Read-Only Files Found" -Color "Yellow"
        $ReadOnlyFiles | ForEach-Object {
            Show-Finding -Type "Read-Only" -Message $_ -Severity "High"
        }
    }

    $DuplicateHashes = $FileHashes.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
    if ($DuplicateHashes.Count -gt 0) {
        Show-Section -Title "Duplicate Hashes Found" -Color "Yellow"
        foreach ($item in $DuplicateHashes) {
            Show-Finding -Type "Hash Collision" -Message "Hash: $($item.Key)" -Severity "Medium"
            $item.Value | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
    }

    if ($TimeMismatchFiles.Count -gt 0) {
        Show-Section -Title "Time Mismatches Found" -Color "Cyan"
        $TimeMismatchFiles | ForEach-Object {
            Show-Finding -Type "Time Mismatch" -Message $_ -Severity "Low"
        }
    }

    if ($SuspiciousCount -eq 0) {
        Show-Section -Title "No Suspicious Findings" -Color "Green"
        Write-Host "No suspicious Prefetch files detected." -ForegroundColor Green
    }

    # Export results
    Write-Host ""
    Show-Section -Title "Export Results" -Color "DarkCyan"
    $ExportChoice = Read-Host "Export results to file? (y/n)"
    if ($ExportChoice -eq "y") {
        $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { "." }
        $OutFile = Join-Path -Path $OutputDir -ChildPath "Prefetch_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

        $ReportContent = @"
==== AMAZE Prefetch Analysis Report ====
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Files Analyzed: $totalFiles
Suspicious Findings: $SuspiciousCount

"@

        if ($EmptyFiles.Count -gt 0) {
            $ReportContent += "=== Empty Files ===`n$($EmptyFiles -join "`n")`n`n"
        }

        if ($ReadOnlyFiles.Count -gt 0) {
            $ReportContent += "=== Read-Only Files ===`n$($ReadOnlyFiles -join "`n")`n`n"
        }

        if ($DuplicateHashes.Count -gt 0) {
            $ReportContent += "=== Duplicate Hashes ===`n"
            foreach ($item in $DuplicateHashes) {
                $ReportContent += "Hash: $($item.Key)`nFiles: $($item.Value -join ", ")`n`n"
            }
        }

        if ($TimeMismatchFiles.Count -gt 0) {
            $ReportContent += "=== Time Mismatches ===`n$($TimeMismatchFiles -join "`n")`n`n"
        }

        try {
            $ReportContent | Out-File -FilePath $OutFile -Encoding UTF8
            Write-Host "Results exported to " -NoNewline -ForegroundColor Cyan
            Write-Host $OutFile -ForegroundColor White
            
            $OpenChoice = Read-Host "Open results file? (y/n)"
            if ($OpenChoice -eq "y") {
                try {
                    Invoke-Item $OutFile
                } catch {
                    Show-Finding -Type "Open Error" -Message "Failed to open file" -Severity "Medium"
                }
            }
        } catch {
            Show-Finding -Type "Export Error" -Message "Failed to export results" -Severity "High"
        }
    }

    # Exit
    Write-Host ""
    Show-Section -Title "Analysis Complete" -Color "DarkGreen"
    Write-Host "Thank you for using AMAZE Prefetch Analyzer" -ForegroundColor Cyan
}
catch {
    Write-Host "An error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    Read-Host "Press Enter to exit"
}