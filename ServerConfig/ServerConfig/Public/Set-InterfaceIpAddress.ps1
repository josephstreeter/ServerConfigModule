function Set-InterfaceIpAddress()
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $false)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $false)][string]$Prefixlength,
        [Parameter(Mandatory = $true)][string]$DefaultGateway
    )
    # . Set-InterfaceIpAddress -IpAddress "172.25.95.117" -Prefixlength 24 -DefaultGateway "172.25.95.1"
    process 
    {
        try 
        {
            $NetAdapters = Get-NetAdapter -ErrorAction Stop
            
            if ($InterfaceIndex -eq 0) 
            { 
                if ($NetAdapters.Name.Count -eq 1)
                {
                    $InterfaceIndex = $NetAdapters[0].ifIndex
                }
                elseif ($NetAdapters.Name.Count -gt 1) 
                {
                    $InterfaceIndex = $NetAdapters | Where-Object { $_.Name -eq "Ethernet" } | Select-Object -ExpandProperty ifIndex
                }
                else 
                {
                    $InterfaceIndex = 5
                }
            }
            
            if ($Prefixlength -eq $null) { $Prefixlength = 24 }
    
            $Params = @{
                InterfaceIndex = $InterfaceIndex
                IPAddress      = $IpAddress
                PrefixLength   = $Prefixlength
                DefaultGateway = $DefaultGateway
            }
            
            $DgwExists = Get-NetRoute | Where-Object { ($_.destinationprefix -eq "0.0.0.0/0") -and ($_.ifIndex -eq $Params.InterfaceIndex) }
            if ($DgwExists) { $DgwExists | Remove-NetRoute -Confirm: $false -ErrorAction Stop }
            
            $IpExists = Get-NetIPAddress | Where-Object { $_.ifIndex -eq $Params.InterfaceIndex -and $_.PrefixOrigin -eq "manual" } 
            if ($IpExists) { $IpExists | Remove-NetIPAddress -Confirm: $false -ErrorAction Stop }
            
            New-NetIPaddress @Params -erroraction Stop
        }
        catch 
        {
            Write-Error $_.Exception.Message
            return
        }
    }
}