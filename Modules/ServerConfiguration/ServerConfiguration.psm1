# Configure Storage

function Invoke-StorageSetup()
{
    [CmdletBinding()]
    param()

    Process
    {
        $Disks = Get-Disk | Where-Object partitionstyle -eq 'raw'
        
        $i = 1
        foreach ($Disk in $Disks)
        {
            $Disks | Initialize-Disk -PartitionStyle GPT -PassThru |
                New-Partition -AssignDriveLetter -UseMaximumSize |
                Format-Volume -FileSystem NTFS -NewFileSystemLabel “Storate$i” -Confirm:$false
            $i++
        }
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

# Configure Local Users <#
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
            Rename-LocalUser -Name "Administrator" -NewName (New-Guid).Guid.substring(0, 20).replace("-", "")
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

# Configure Time
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
            
        <#
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

# Configure Baseline
function Import-LgpoPolicy([string] $lgpoParams)
{
    #[CmdletBinding()]
    #Param()
    
    #ShowProgress "Running LGPO.exe $lgpoParams"
    #LogA (cmd.exe /c "LGPO.exe $lgpoParams 2>&1")

    #RunLGPO "/v /g  ..\GPOs\$gpoGuid"
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

# Configure Network Interfaces
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

function Disable-NetBios()
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



# Configure Remote Access

Function Enable-WinRM()
{
    [CmdletBinding()]
    param ()
    
    process 
    {
        try
        {
            
            Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return $null
        }
        
        try 
        {
            If ((Get-Service WinRM).status -eq "Stopped") { Start-Service WinRM }
        
            $Name = $(Get-WmiObject -class win32_computersystem).name
            $DNSName = $(Get-WmiObject -class win32_computersystem).name + "." + $(Get-WmiObject -class win32_computersystem).domain
        
            $Cert = New-SelfSignedCertificate -DnsName $Name, $DNSName.ToLower() -CertStoreLocation Cert:\LocalMachine\My
            $Config = '@{Hostname="' + $Name + '";CertificateThumbprint="' + $cert.Thumbprint + '"}'
            
            winrm create winrm/config/listener?Address=*+TransPort=HTTPS $Config
            #Enable-PSRemoting -SkipNetworkProfileCheck -Force  <===================================================== Can I switch to this?
            If (-Not(Get-NetFirewallRule "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue)) 
            {
                New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" `
                    -Name "Windows Remote Management (HTTPS-In)" `
                    -Profile Any `
                    -LocalPort 5986 `
                    -Protocol TCP `
                    -ErrorAction Stop
            }    
        }
        catch
        {
            Write-Error $_.Exception.Message
        }
    }
}

function Enable-RemoteDesktop()
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

function Install-OpenSSH()
{
    [CmdletBinding()]
    param ()
    
    process
    {
        try
        {
            $SSHServer = Get-WindowsCapability -Online | Where-Object { $_.name -match "OpenSSH-Server" }
            if ($SSHServer.State -ne "Installed")
            {
                Add-WindowsCapability -Online -Name $SSHServer.name -erroraction stop
            }    
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return $null
        }
        
        try
        {
            $SSHClient = Get-WindowsCapability -Online | Where-Object { $_.name -match "OpenSSH-Client" }
            if ($SSHServer.State -ne "Installed")
            {
                Add-WindowsCapability -Online -Name $SSHClient.name -erroraction stop
            }
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return $null
        }

        try
        {
            Start-Service -Name sshd -erroraction stop
            Set-Service -Name sshd -StartupType "Automatic" -erroraction stop    
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return $null
        }

        try
        {
            $SSHServerFwRule = Get-NetFirewallRule -name sshd
            if (-not ($SSHServerFwRule))
            {
                New-NetFirewallRule -Name "sshd" -DisplayName "OpenSSH Server" -Enabled true -Direction "Inbound" -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction Stop 
            }
        }
        catch
        {
            Write-Error $_.Exception.Message
        }
    }
}

# Configure Hostname
function Set-HostName()
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)][string]$NewName,
        [Parameter(Mandatory = $true)][switch]$Restart
    )
        
    process
    {
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