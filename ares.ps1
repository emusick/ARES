<#
.SYNOPSIS
ARES (Automated REsponse Script) provides a wrapper to PowerShell forensic scripts to automate the consistent collection of artifacts.

.DESCRIPTION
ARES (Automated REsponse Script) provides a wrapper to PowerShell forensic scripts to automate the consistent collection of artifacts.

Author: Erik Musick
Version: 0.0

.PARAMETER

.EXAMPLE
ares.ps1 -Type C -Case 12345 -Target \\hostname\c$

.NOTES
Currently creates fake files to demonstrate
- Case folder structure
- Expected menu
- Chain of Custody creation
- Narrative creation

.LINK
github

#>

$menuIncident=@"
 C| Common
 M| Malware
 O| Other
 Q| Quit

Select an incident type
"@

function Invoke-Title {
    Write-Host ""
    Write-Host -ForegroundColor Cyan     "    :::     :::::::::  :::::::::  :::::::: "
    Write-Host -ForegroundColor Cyan     "  :+: :+:   :+:    :+: :+:       :+:    :+:"
    Write-Host -ForegroundColor DarkCyan " +:+   +:+  +:+    +:+ +:+       +:+       "
    Write-Host -ForegroundColor DarkCyan "+#++:++#++: +#++:++#:  +#++:++#  +#++:++#++"
    Write-Host -ForegroundColor DarkGray "+#+     +#+ +#+    +#+ +#+              +#+"
    Write-Host -ForegroundColor DarkGray "#+#     #+# #+#    #+# #+#       #+#    #+#"
    Write-Host -ForegroundColor Gray     "###     ### ###    ### #########  ######## "
    Write-Host ""
    Write-Host ""
}

function Check-IsAdmin {
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole)) {
        # We are running "as Administrator" - so change the title and background color to indicate this
        $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
        $Host.UI.RawUI.BackgroundColor = "DarkRed"
        clear-host
    }
    else {
        # We are not running "as Administrator" - so relaunch as administrator
   
        #create a new process object that starts PowerShell
        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
        # Specify the current script path and name as a parameter
        $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
        # Indicate that the process should be elevated
        $newProcess.Verb = "runas";
   
        # Start the new process
        [System.Diagnostics.Process]::Start($newProcess);
   
        # Exit from the current, unelevated, process
        exit
   }
}

function Invoke-CaseCreation {
    $caseNumber = Read-Host -Prompt "Enter case number"
    Write-Host ""

    try { New-Item "./$caseNumber" -type Directory -ErrorAction Stop | Out-Null }
    catch {
        Write-Warning "Unable to create directory structure for $caseNumber"
        exit
    }

    New-Item "./$caseNumber/Report" -type Directory | Out-Null
    New-Item "./$caseNumber/Report/Auxiliary" -type Directory | Out-Null
    New-Item "./$caseNumber/Image" -type Directory | Out-Null
    New-Item "./$caseNumber/Artifact" -type Directory | Out-Null

    cd $caseNumber
}

function Invoke-Menu {
    [cmdletbinding()]
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Enter the menu name")]
        [ValidateNotNullOrEmpty()]
        [string]$menu,
        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$title = "Menu title"
    )

    $menuPrompt=$title
    $menuPrompt+="`n"
    $menuPrompt+="-"*$title.Length
    $menuPrompt+="`n"
    $menuPrompt+=$menu
     
    Read-Host -Prompt $menuPrompt
}

function Invoke-MenuIncident {
    Switch( Invoke-Menu -menu $menuIncident -title "ARES: Incident type" ) {
        "C" { Invoke-IRCommon }
        "M" { Invoke-IRMalware }
        "O" { Invoke-IROther }
        "Q" { exit }
        Default {
            Write-Host ""
            Write-Warning "Invalid choice. Select a valid option."
            Write-Host ""
        }
    }
}

function Invoke-IRCommon {
    Write-Host "Run common framework"
    Copy-ForensicFile -Path "C:\Windows\System32\config\SAM" -Destination ".\Artifact\"
}

function Invoke-IRMalware {
    Write-Host "Run malware framework"
}

function Invoke-IROther {
    Write-Host "Run other framework"
}

function Get-PowerForensics {
    # Is PowerForeniscs loaded?
    if ( -Not $(Get-Module -Name PowerForensics)) {
        Write-Warning "Module not loaded"
        # Is PowerForensics available?
        if ( Get-Module -ListAvailable -Name PowerForensics ) {
            Write-Host "Found PowerForensics"
            Import-Module PowerForensics
        }
     else {
        # Download PowerForensics
        Write-Warning "PowerForensics not found"
        Write-Host "Downloading PowerForensics"
        $url = "https://github.com/Invoke-IR/PowerForensics/archive/master.zip"
        $output = ".\powerforensics.zip"

        (New-Object System.Net.WebClient).DownloadFile($url, $output)

        # Install PowerForensics
        Write-Host "Installing PowerForensics"
        Expand-Archive -Path ".\powerforensics.zip" -DestinationPath ".\"

        Write-Host "Move .\PowerForensics-master\Modules\PowerForensics to a module path."
        Write-Host "Current paths include: $env:PSModulePath"
        #Import-Module PowerForensics
        exit
    }
    }
# check if available
    sleep 2

}

function Write-ChainCustody {
    Write-Host "Stub for Chain of Custody"
}

function Write-Narrative {
    Write-Output "On $(Get-Date -Format u), (Get-LocalUser) (Department) executed ARES to collect common and (incident_type) artifacts. See Chain of Custody, (coc_artifact), for more details." | Out-File ".\Report\Narrative.txt"
}

Get-PowerForensics

Check-IsAdmin

Clear-Host
Invoke-Title
Invoke-CaseCreation
Invoke-MenuIncident

Write-ChainCustody
Write-Narrative
