function Set-InterfaceDnsClient()
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $false)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][array]$DnsServerAddresses,
        [Parameter(Mandatory = $true)][string]$DnsSuffix
    )

    process 
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
        
        $ParamDnsServerAddresses = @{
            InterfaceIndex  = $InterfaceIndex
            ServerAddresses = $DnsServerAddresses
        }

        $ParamDnsSuffix = @{
            InterfaceIndex           = $InterfaceIndex
            ConnectionSpecificSuffix = $DnsSuffix
            UseSuffixWhenRegistering = $true
        }
        
        try 
        {
            Set-DNSClientServerAddress @ParamDnsServerAddresses -erroraction Stop
            Set-DnsClient @ParamDnsSuffix -erroraction Stop

            # Future use
            #Set-DnsClientGlobalSetting -SuffixSearchList $SearchSuffixList 
        }
        catch 
        {
            Write-Error $_.Exception.Message
            Return $null
        }
    }
}