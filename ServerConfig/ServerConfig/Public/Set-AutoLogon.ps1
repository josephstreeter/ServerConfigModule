Function Set-AutoLogon()
{
    [CmdletBinding()]
    Param(    
        [Parameter(Mandatory = $True)][String]$Username,
        [Parameter(Mandatory = $True)][String]$Secret,
        [Parameter(Mandatory = $False)][AllowEmptyString()][int32]$AutoLogonCount,
        [Parameter(Mandatory = $False)][AllowEmptyString()][String]$Script
    )

    #Registry path declaration
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    try
    {
        #setting registry values
        Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String  
        Set-ItemProperty $RegPath "DefaultUsername" -Value "$Username" -type String  
        Set-ItemProperty $RegPath "DefaultPassword" -Value "$Secret" -type String
        if ($AutoLogonCount)
        {
            Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
        }
        else
        {
            Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
        }
        
        if ($Script)
        {
            Set-ItemProperty $RegROPath "(Default)" -Value "$Script" -type String
        }
        else
        {
            Set-ItemProperty $RegROPath "(Default)" -Value "" -type String
        }        
    }
    catch
    {
        Write-Output "An error had occured $Error"
    }
}