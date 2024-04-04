function Disable-InterfaceNetBios()
{
    [CmdletBinding()]
    param ()

    process 
    {
        $NetbiosOptionsVlaues = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions
        $Counter = 0
        Foreach ($NetbiosOptionsVlaue in $NetbiosOptionsVlaues)
        {
            if ($NetbiosOptionsVlaue.NetbiosOptions -ne 2)
            { 
                $Counter += 1 
            }
        }
        if ($Counter -eq 0) 
        { 
            Write-Output "No Interfaces have NetBIOS enabled"
            Return $null
        }
        else 
        { 
            Write-Output "Interfaces have NetBIOS enabled" 
        }
    }
}