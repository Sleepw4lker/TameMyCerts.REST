[CmdletBinding()]
param()

# Ensuring the Script will be run with Elevation
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error -Message "This must be run as Administrator! Aborting."
    Return
}

[System.Diagnostics.EventLog]::CreateEventSource("AdcsToRest", 'Application')