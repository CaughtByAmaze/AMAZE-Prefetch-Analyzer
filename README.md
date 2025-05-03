# AMAZE Prefetch Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This tool is a simple PowerShell script (compiled as an executable for ease of use) designed to analyze Windows Prefetch files (`.pf`) for potential signs of tampering. It performs multiple checks, including:

* **Empty Files:** Identifies Prefetch files with zero size.
* **Read-Only Files:** Detects Prefetch files that have the read-only attribute set.
* **Duplicate Hashes:** Calculates SHA256 hashes of the Prefetch files and reports any files with identical hashes (excluding the same file).
* **Time Mismatches:** Checks for discrepancies between the last run time and last modified time of the Prefetch files.

These checks can help in identifying potentially suspicious Prefetch files that might have been manipulated by malware or unauthorized users.

## How to Use the Executable

1.  **Download the Executable:** Obtain the `AMAZE_Prefetch_Analyzer.exe` file from the releases section of this repository (if you've created one) or after compiling the provided PowerShell script.
2.  **Run the Executable:** Simply double-click the `AMAZE_Prefetch_Analyzer.exe` file.
3.  **Follow the Prompts:** The tool will run in your command prompt or terminal:
    * It will display a header and start analyzing the Prefetch files in the default Windows Prefetch directory (`C:\Windows\Prefetch`).
    * Progress will be shown during the analysis.
    * A summary of the findings, including the total files analyzed and any suspicious files detected, will be displayed.
    * You will be prompted if you want to export the results to a text file (`.txt`). If you choose "y", the report will be saved in the same directory as the executable.
    * Press Enter to exit the tool.

## Potential Findings and Interpretation

* **Empty Files:** Could indicate corruption or intentional deletion of file content.
* **Read-Only Files:** Prefetch files are typically not read-only. This attribute might be set to prevent modification.
* **Duplicate Hashes:** While some legitimate files might have the same content, unexpected duplicates in the Prefetch folder could warrant further investigation.
* **Time Mismatches:** Significant differences between the last run and last modified times could suggest tampering with the file metadata.

**Note:** This tool provides indicators of potential tampering. Further analysis might be required to confirm malicious activity.

## Building from the PowerShell Script

If you prefer to run the PowerShell script directly or want to modify it:

1.  **Save the Script:** Save the provided PowerShell code as a `.ps1` file (e.g., `AMAZE_Prefetch_Analyzer.ps1`).
2.  **Run in PowerShell:** Open PowerShell and navigate to the directory where you saved the script. Then run:
    ```powershell
    .\AMAZE_Prefetch_Analyzer.ps1
    ```
3.  **Compile to Executable (Optional):** You can use tools like PS2EXE to compile the PowerShell script into a standalone executable (`.exe`) for easier distribution and use on systems without readily available PowerShell execution.

## License

This project is licensed under the [MIT License](LICENSE). See the `LICENSE` file for more information.

## Author

[CaughtByAmaze]
