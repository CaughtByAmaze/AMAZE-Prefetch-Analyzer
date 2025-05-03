# AMAZE Prefetch Analyzer v1.2
# Enhanced with time tolerance and reliability improvements

# Clear the console for a clean start
Clear-Host

# Ensure the script continues running even if there's an error
$ErrorActionPreference = "Stop"

# Set the path to the Prefetch directory
$PrefetchPath = "$env:SystemRoot\Prefetch"

# Set time tolerance range for false positive reduction (30-45 seconds)
$MinTimeTolerance = 30
$MaxTimeTolerance = 45

# Custom UI Functions
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
    Write-Host -NoNewline ("-" * $remaining)
    Write-Host -NoNewline ("] $Percent%")

    if ($Percent -eq 100) {
        Write-Host ""
    }
}

function Show-Finding {
    param([string]$Type, [string]$Message, [string]$Severity = "Medium")

    $colors = @{
        "High"   = "Red"
        "Medium" = "Yellow"
        "Low"    = "Cyan"
        "Info"   = "Gray"
    }

    $symbols = @{
        "High"   = "‼"
        "Medium" = "!"
        "Low"    = "i"
        "Info"   = "·"
    }

    $color = $colors[$Severity]
    $symbol = $symbols[$Severity]

    Write-Host ("[$symbol] ").PadRight(6) -NoNewline -ForegroundColor $color
    Write-Host "$Type".PadRight(15) -NoNewline -ForegroundColor $color
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

try {
    # Display the main header
    Show-Header -Title "AMAZE Prefetch Analyzer v1.1"
    Write-Host "Version 1.1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "Analyzing Windows Prefetch files for signs of tampering..." -ForegroundColor Gray
    Write-Host "Note: Flagging time differences between $MinTimeTolerance-$MaxTimeTolerance seconds" -ForegroundColor DarkYellow
    Write-Host ""

    # Check if the Prefetch directory exists
    if (-not (Test-Path $PrefetchPath)) {
        Show-Finding -Type "Critical Error" -Message "Prefetch directory not found at '$PrefetchPath'!" -Severity "High"
        Read-Host "Press Enter to exit"
        exit
    }

    # Get all .pf files in the Prefetch directory
    Show-Progress -Message "Scanning Prefetch directory" -Percent 10
    $PrefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue

    if (-not $PrefetchFiles -or $PrefetchFiles.Count -eq 0) {
        Show-Finding -Type "Warning" -Message "No Prefetch files found in directory." -Severity "Medium"
        Read-Host "Press Enter to exit"
        exit
    }

    # Initialize arrays to store results
    $EmptyFiles = @()
    $ReadOnlyFiles = @()
    $FileHashes = @{}
    $TimeMismatchFiles = @()
    $SuspiciousCount = 0

    # Perform the analysis of each prefetch file
    Show-Section -Title "File Analysis Progress" -Color "Cyan"
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

        # Check time mismatches with tolerance (30-45 seconds)
        $LastRunTime = $File.LastAccessTime
        $LastModified = $File.LastWriteTime
        $TimeDifference = $LastModified - $LastRunTime
        $AbsDifference = [math]::Abs($TimeDifference.TotalSeconds)

        # Only flag if difference is between 30-45 seconds
        if ($AbsDifference -ge $MinTimeTolerance -and $AbsDifference -le $MaxTimeTolerance) {
            $TimeMismatchFiles += "$($File.Name) (Last Run: $LastRunTime, Modified: $LastModified, Difference: $([math]::Round($TimeDifference.TotalSeconds))s)"
            $SuspiciousCount++
        }
    }

    # Display results
    Clear-Host
    Show-Header -Title "Analysis Results"

    # Summary section
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

    # Findings sections
    if ($EmptyFiles.Count -gt 0) {
        Show-Section -Title "Empty Files Found" -Color "Red"
        $EmptyFiles | ForEach-Object {
            Show-Finding -Type "Empty File" -Message $_ -Severity "High"
        }
    }

    if ($ReadOnlyFiles.Count -gt 0) {
        Show-Section -Title "Read-Only Files Found" -Color "Yellow"
        $ReadOnlyFiles | ForEach-Object {
            Show-Finding -Type "Read-Only" -Message $_ -Severity "Medium"
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

    # If no suspicious findings
    if ($SuspiciousCount -eq 0) {
        Show-Section -Title "No Suspicious Findings" -Color "Green"
        Write-Host "No suspicious Prefetch files detected." -ForegroundColor Green
        Write-Host "All analyzed files appear normal." -ForegroundColor Gray
    }

    # Export results
    Write-Host ""
    Show-Section -Title "Export Results" -Color "DarkCyan"
    $ExportChoice = Read-Host "Do you want to export the results to a file? (y/n)"
    if ($ExportChoice -eq "y") {
        # Determine the output directory
        $OutputDir = if ($PSScriptRoot) {
            $PSScriptRoot
        } else {
            "." # Current working directory
        }

        # Save the output file in the determined directory
        $OutFile = Join-Path -Path $OutputDir -ChildPath "Prefetch_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

        # Create string for output
        $ReportContent = @"
==== AMAZE Prefetch Analysis Report ====
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Files Analyzed: $totalFiles
Suspicious Findings: $SuspiciousCount
Time Comparison Range: $MinTimeTolerance-$MaxTimeTolerance seconds

"@

        if ($EmptyFiles.Count -gt 0) {
            $ReportContent += "=== Empty Files ===`n"
            $ReportContent += ($EmptyFiles -join "`n") + "`n`n"
        }

        if ($ReadOnlyFiles.Count -gt 0) {
            $ReportContent += "=== Read-Only Files ===`n"
            $ReportContent += ($ReadOnlyFiles -join "`n") + "`n`n"
        }

        if ($DuplicateHashes.Count -gt 0) {
            $ReportContent += "=== Duplicate Hashes ===`n"
            foreach ($item in $DuplicateHashes) {
                $ReportContent += "Hash: $($item.Key)`n"
                $ReportContent += "Files: $($item.Value -join ", ")`n`n"
            }
        }

        if ($TimeMismatchFiles.Count -gt 0) {
            $ReportContent += "=== Time Mismatches ===`n"
            $ReportContent += ($TimeMismatchFiles -join "`n") + "`n`n"
        }

        if ($SuspiciousCount -eq 0) {
            $ReportContent += "=== No Suspicious Findings ===`n"
            $ReportContent += "All analyzed files appear normal.`n"
        }

        try {
            $ReportContent | Out-File -FilePath $OutFile -Encoding UTF8
            Write-Host "Results exported to " -NoNewline -ForegroundColor Cyan
            Write-Host $OutFile -ForegroundColor White
        } catch {
            Show-Finding -Type "Export Error" -Message "Failed to export results: $($_.Exception.Message)" -Severity "High"
        }
    } else {
        Write-Host "Results not exported." -ForegroundColor Gray
    }

    # Final message
    Write-Host ""
    Show-Section -Title "Analysis Complete" -Color "DarkGreen"
    Write-Host "Thank you for using AMAZE Prefetch Analyzer" -ForegroundColor Cyan
}
catch {
    Write-Host "An unexpected error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    # Keep the window open until user presses Enter
    Read-Host "Press Enter to exit"
}