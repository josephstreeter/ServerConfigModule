function Set-ServerTimezone()
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][string]$TimeZone
    )

    try 
    {
        if (-not ($TimeZone)) { $TimeZone = "Central Standard Time" }
        Set-TimeZone -Name $TimeZone -ErrorAction Stop    
    }
    catch 
    {
        Write-Error $_.Exception.Message
    }
}