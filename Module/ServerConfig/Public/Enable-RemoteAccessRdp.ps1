function Enable-RemoteAccessRdp()
{
    [CmdletBinding()]
    param ()

    process 
    {
        try 
        {
            $RDP = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices
            $RDPNLA = Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
    
            Write-Output "Enable RDP and Network Level Security"
            if ($RDP.AllowTSConnections -ne 1) { $RDP.SetAllowTsConnections(1) }
            if ($RDPNLA.UserAuthenticationRequired -ne 1) { $RDPNLA.SetUserAuthenticationRequired(1) }    
        }
        catch 
        {
            Write-Error $_.Exception.Message
            Return $null
        }
    }
}