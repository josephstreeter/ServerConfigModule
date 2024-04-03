[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)][string]$HostName = "IAMDCPRD01",
    [Parameter(Mandatory = $false)][string]$IPAddress = "192.168.0.100",
    [Parameter(Mandatory = $false)][string]$Prefixlength = "24",
    [Parameter(Mandatory = $false)][string]$DefaultGateway = "192.168.0.1",
    [Parameter(Mandatory = $false)][string[]]$DNSServers = ('8.8.8.8','4.4.2.2'),
    [Parameter(Mandatory = $false)][string]$DomainName = 'MATC.Madison.Login',
    [Parameter(Mandatory = $false)][string[]]$DNSSuffixSearchList = "MATC.Madison.Login"
)

Begin
{
    <#
    function Set-NetworkInterface()
    {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)][string]$IPAddress,
            [Parameter(Mandatory = $true)][string]$Prefixlength,
            [Parameter(Mandatory = $true)][string]$DefaultGateway,
            [Parameter(Mandatory = $true)][string[]]$DNSServers,
            [Parameter(Mandatory = $true)][string[]]$DomainName,
            [Parameter(Mandatory = $false)][string[]]$DNSSuffixSearchList
        )
        
        $Adapter = Get-NetAdapter -name Ethernet

        New-NetIPAddress `
            -InterfaceIndex $Adapter.IfIndex `
            -IPAddress $IPAddress `
            -PrefixLength $Prefixlength `
            -DefaultGateway $DefaultGateway

        Set-DnsClientServerAddress `
            -InterfaceIndex $Adapter.IfIndex `
            -ServerAddresses ($DNSServers)

        Set-DnsClient `
            -InterfaceIndex $Adapter.IfIndex `
            -UseSuffixWhenRegistering $true `
            -RegisterThisConnectionsAddress $True `
            -ConnectionSpecificSuffix $ConnSuffix 

        Set-DnsClientGlobalSetting `
            -SuffixSearchList $DNSSuffixSearchList 
    }

    function Disable-NetBios()
    {
        [CmdletBinding()]
        param ()

        process 
        {
            $NetbiosOptionsVlaues = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions
            $Counter = 0
            Foreach($NetbiosOptionsVlaue in $NetbiosOptionsVlaues )
            {
                if($NetbiosOptionsVlaue.NetbiosOptions -ne 2)
                { 
                    $Counter+=1 
                }
            }
            if($Counter -eq 0) 
            { 
                Write-Output $true 
            }
            else 
            { 
                Write-Output $false 
            }
        }
    }

    function Set-RemoteDesktop()
    {
        [CmdletBinding()]
        param ()

        try 
        {
            $RDP = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices
            if ($RDP.AllowTSConnections -ne 1)
            {
                $RDP.SetAllowTsConnections(1)
                Write-Verbose "Remote Desktop Protocol enabled"
            }
            
            
            $RDPNLA = Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
            
            if ($RDPNLA.UserAuthenticationRequired -ne 1)
            {
                $RDPNLA.SetUserAuthenticationRequired(1)
                Write-Verbose "Network Level Authentication configured"
            }
            
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }

    function Set-WinRM()
    {
        [CmdletBinding()]
        Param()
            
        If ((Get-Service WinRM).status -eq "Stopped") { Start-Service WinRM }

        $DNSName = $(Get-WmiObject -class win32_computersystem).name + "." + $(Get-WmiObject -class win32_computersystem).domain
        $Name = $(Get-WmiObject -class win32_computersystem).name

        $cert = New-SelfSignedCertificate -DnsName $ENV:COMPUTERNAME, "$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower() -CertStoreLocation Cert:\LocalMachine\My
        $Config = '@{Hostname="' + $ENV:COMPUTERNAME + '";CertificateThumbprint="' + $cert.Thumbprint + '"}'
        winrm create winrm/config/listener?Address=*+TransPort=HTTPS $Config

        If (-Not(get-netfirewallrule "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue)) 
        {
            New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" `
                -Name "Windows Remote Management (HTTPS-In)" `
                -Profile Any `
                -LocalPort 5986 `
                -Protocol TCP
        }
    }

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

    function RunLGPO([string] $lgpoParams)
    {
        #[CmdletBinding()]
        #Param()
        
        ShowProgress "Running LGPO.exe $lgpoParams"
        LogA (cmd.exe /c "LGPO.exe $lgpoParams 2>&1")

        #RunLGPO "/v /g  ..\GPOs\$gpoGuid"
    }

    Function Install-Roles 
    {
        [CmdletBinding()]
        Param()
        
        if ($Role -eq "ADDS")
        {
            Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools
            Add-WindowsFeature -Name "DNS" -IncludeAllSubFeature -IncludeManagementTools
            Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools
        }
    }

    Function Set-LocalUsers()
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)][string]$Secret
        )

        try 
        {
            $Password = ConvertTo-SecureString -AsPlainText ((New-Guid).Guid + "-" + $Secret) -Force
            if (Get-LocalUser -Name "Administrator")
            {
                Set-LocalUser -Name "Administrator" -Description "" -Password $Password
                Disable-LocalUser -Name "Administrator"
                Rename-LocalUser -Name "Administrator" -NewName (New-Guid).Guid.substring(0,20).replace("-","")
            }
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
        
        try 
        {
            if (-not (Get-LocalUser -Name "xNimda"))
            {
                $AdminName = 'xNimda'
                $params = @{
                    Name        = $AdminName
                    Password    = $Password
                    FullName    = $AdminName
                    Description = 'Local Admin Account'
                }
                New-LocalUser @params -ErrorAction Stop
                Add-LocalGroupMember -Group "Administrators" -Member $AdminName -ErrorAction Stop
            }
            
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }

    function Set-ServerTimezone()
    {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)][string]$TimeZone
        )

        try 
        {
            Set-TimeZone -Name $TimeZone -ErrorAction Stop    
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }
#>
    function Set-PowerSettings()
    {
        [CmdletBinding()]
        param ()

        try 
        {
            Invoke-Command -ScriptBlock { 
                powercfg.exe -h off 
                Powercfg.exe -setacvalueindex scheme_current sub_processor PERFEPP 0
                Powercfg.exe -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
                Powercfg.exe -setactive scheme_current
                powercfg.exe -x -monitor-timeout-ac 0
                powercfg.exe -x -monitor-timeout-dc 0
                powercfg.exe -x -disk-timeout-ac 0
                powercfg.exe -x -disk-timeout-dc 0
                powercfg.exe -x -standby-timeout-ac 0
                powercfg.exe -x -standby-timeout-dc 0
                powercfg.exe -x -hibernate-timeout-ac 0
                powercfg.exe -x -hibernate-timeout-dc 0
            } -ErrorAction stop
            
            https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning
            
            #>

            
            # This doesn't work
            $powerPlan = Get-CimInstance -Name root\cimv2\power -Query "SELECT * FROM Win32_PowerPlan WHERE ElementName = 'High Performance'"
            $powerPlan.Activate()
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }

    Function Set-PageFile()
    {
        [CmdletBinding()]
        param ()

        try 
        {
            $MemorySize = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum #/1gb
            $PageFileSize = ([Math]::Round($MemorySize + ($MemorySize * .1), 0))
            
            $PageFile = Get-CimInstance -ClassName Win32_ComputerSystem
            $PageFile.AutomaticManagedPagefile = $false
            Set-CimInstance -InputObject $PageFile

            $PageFileSet = Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object { $_.name -eq "$ENV:SystemDrive\pagefile.sys" }
            
            # Breaks here
            
            $PageFileSet.InitialSize = $PageFileSize
            $PageFileSet.MaximumSize = $PageFileSize
            Set-CimInstance -InputObject $PageFileSet -ErrorAction Stop
        }
        catch 
        {
            write-Error $_.Exception.Message
        }
    }

    function Set-StoragePolicy()
    {
        [CmdletBinding()]
        param ()

        try 
        {
            $NewDiskPolicy = Get-StorageSetting | Select-Object -ExpandProperty NewDiskPolicy 
            if ($NewDiskPolicy -ne "OnlineAll") 
            { 
                Set-StorageSetting -NewDiskPolicy OnlineAll -ErrorAction Stop 
            }
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }

    function Set-KmsServer()
    {
        [CmdletBinding()]
        param 
        (
            [Parameter(Mandatory = $false)][string]$KmsServer
        )

        #https://theitbros.com/activate-windows-with-kms-server/#penci-How-to-Activate-Windows-Computer-with-KMS-License-Server
        try 
        {
            if ($KmsServer)
            {
                Invoke-Command -ScriptBlock { C:\Windows\System32\slmgr.vbs /skms $KmsServer } -ErrorAction Stop
            }
            
            Invoke-Command -ScriptBlock { C:\Windows\System32\slmgr.vbs /ato } -ErrorAction Stop    
        }
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }

    function Disable-IeEnhancedSecurity()
    {
        Try
        {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
        }
        Catch
        {
            Write-Warning $_.Exception.Message
            Break
        }
    }

    function Rename-Host()
    {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)][String]$Hostname
        )

        Rename-Computer -NewName $HostName -force
    }
}

Process
{
    #Set-NetworkInterface -IPAddress $IPAddress -PrefixLength $Prefixlength -defaultGateway $DefaultGateway -DNSServers $DNSServers -DomainName $DomainName -DNSSuffix $DNSSuffixSearchList
    #Disable-NetBios
    #Set-RemoteDesktop
    #Set-WinRM
    #Set-LocalUsers -Secret "GoonieGooGooGus2015_!"
    #Set-ServerTimezone -TimeZone "Central Standard Time"
    #Set-PowerSettings
    #Set-PageFile
    #Set-StoragePolicy
    #Set-KmsServer
    #Disable-IeEnhancedSecurity
    Set-AutoLogon -Username "$env:USERdomain\$env:USERNAME" -Secret "iw2slep!"
    Rename-Host -Hostname $HostName
}

End 
{

}
<#
#Get disks size and ID number
$Disks = Get-PhysicalDisk | Select-Object DeviceID, @{Name="Size(GB)"; Expression={"{0:N2}" -f ($_.Size / 1GB)}}
$Disks

# Prompt for disk ID number
$diskNumber = Read-Host "Enter the disk ID number"

# Initialize the disk as GPT
Initialize-Disk -Number $diskNumber -PartitionStyle GPT

# Prompt for drive letter
$driveLetter = Read-Host "Enter the drive letter for the partition (e.g., C, D, E)"

# Create a new partition using the maximum available space
New-Partition -DiskNumber $diskNumber -UseMaximumSize -DriveLetter $driveLetter

# Format the partition as NTFS
$partition = Get-Partition -DiskNumber $diskNumber | Where-Object { $_.Type -eq 'Basic' }
Format-Volume -Partition $partition -FileSystem NTFS -Confirm:$false

# Prompt for label
$label = Read-Host "Enter the label for the partition"

# Set the label for the partition
Set-Volume -DriveLetter $driveLetter -NewFileSystemLabel $label

Write-Host "Partition creation and formatting completed."
#>

<#

https://github.com/sysadmintutorials/windows-server-2019-powershell-ad-install-config/blob/master/1-Basic-Server-Config.ps1

#>

<#
In vcenter go to the actions for the VM and select edit settings > CD/DVD drive1 from dropdown select Datastore ISO File, Status Connect At Power On Browse for CD/DVD Media in datatstore serverintel_nfs_01a_template > Windows ISOs and select the appropriate ISO and OK  
Enable change block  tracking  (CBT) in VCenter: 

To enable CBT in a virtual machine: 
Add the ctkEnabled parameter under Name and then set its value to TRUE. 

Install VMware Tools using "Typical" install  


Server OS settings  

Install Server 2022 with desktop experience or core  

! Set local admin password  

https://theitbros.com/activate-windows-with-kms-server/#penci-How-to-Activate-Windows-Computer-with-KMS-License-Server
set KMS server - cscript //nologo "C:\Windows\System32\slmgr.vbs" /skms kmsprd01.matc.madison.login  
cscript //nologo "C:\Windows\System32\slmgr.vbs" /ato

Set Maximum Que Depth:                                                                                                                        REG ADD HKLM\SYSTEM\CurrentControlSet\services\pvscsi\Parameters\Device /v  DriverParameter /t REG_SZ /d “RequestRingPages=32,MaxQueueDepth=254” 

!powercfg -h off (to turn off hibernation)  

!Set Time Zone to Central Time  

!Enable Remote Desktop

Install updates  

Run script for PRTG monitoring to configure local firewall and install WMI&SNMP features "\\naf01b\ENShare2\Infrastructure\Monitoring-PRTG\scripts\setmgmt.cmd"

!Disable NetBIOS over TCP/IP on network adapter

!Change power options to high performance

!Change storage policy to Online all disks 
!Get-StorageSetting | Select-Object NewDiskPolicy 
!Set-StorageSetting -NewDiskPolicy OnlineAll 


​Add to PRTG. 
Add to RUBRIK
​WSUS add to group for auto patching or leave as download only for manual patching. (Patching should be configured through Azure Arc) 
​Add Splunk agent 
Run script to onboard server to security center. 
Run script to onboard server to Azure ARC. 
#>