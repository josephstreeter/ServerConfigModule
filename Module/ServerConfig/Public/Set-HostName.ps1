function Set-HostName()
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)][string]$NewName,
        [Parameter(Mandatory = $true)][switch]$Restart
    )

    try
    {
        Rename-Computer -NewName $NewName -ErrorAction Stop
        if ($Restart) { Restart-Computer -Force }
    }
    catch
    {
        Write-Error $_.Exception.Message
        Return $null
    }
}