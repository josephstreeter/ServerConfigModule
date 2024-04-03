# Configure Windows Server Roles

function Install-ADDSRoles()
{
    [CmdletBinding()]
    param ()
    
    process
    {
        try
        {
            $WindowsFeatures = "ad-domain-services", "DNS", "gpmc"
            
            foreach ($WindowsFeature in $WindowsFeatures)
            {
                $WindowsFeatureState = Get-WindowsFeature -Name $WindowsFeature

                if ($WindowsFeatureState.Installed -eq $false)
                {
                    Add-WindowsFeature -Name $WindowsFeature -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop
                }
                else 
                {
                    Write-Output ("{0} already installed" -f $WindowsFeature)
                }
            }
        }
        catch   
        {
            Return $null
        }
    }
}

function New-ADDSForest 
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)][securestring]$SafeModeAdministratorPassword,
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$DomainNetbiosName,
        [Parameter(Mandatory = $false)][string]$DomainMode,
        [Parameter(Mandatory = $false)][string]$ForestMode, 
        [Parameter(Mandatory = $false)][string]$DatabasePath, 
        [Parameter(Mandatory = $false)][string]$LogPath,
        [Parameter(Mandatory = $false)][string]$SysvolPath
    )
    # New-ADDSForest -SafeModeAdministratorPassword $SMAP -DomainName ad.mc.edu -DomainNetbiosName AD -DomainMode default -ForestMode default
    
    process 
    {
        $WindowsFeatures = "AD-Domain-Services", "DNS", "gpmc"
        foreach ($WindowsFeature in $WindowsFeatures)
        {
            if ((Get-WindowsFeature $WindowsFeature).installed -ne $true)
            {
                Write-Error -Message ("Missing requried role - {0}" -f $WindowsFeature)
                Return $Null
            }
            else 
            {
                Write-Output ("Windows Feature '{0}' already installed" -f $WindowsFeature)
            }
        }
        
        
        if (-Not ($DomainMode)) { $DomainMode = "WinThreshold" }
        if (-Not ($ForestMode)) { $ForestMode = "WinThreshold" }
        
        $params = @{
            DomainMode                    = $DomainMode
            ForestMode                    = $ForestMode
            SafeModeAdministratorPassword = $SafeModeAdministratorPassword
            InstallDns                    = $true
            NoRebootOnCompletion          = $false
            CreateDnsDelegation           = $false
            DomainName                    = $DomainName
            DomainNetbiosName             = $DomainNetbiosName
            Force                         = $true 
        }

        if ($DatabasePath) { $params += @{DatabasePath = $DatabasePath } }
        if ($LogPath) { $params += @{LogPath = $LogPath } }
        if ($SysvolPath) { $params += @{SysvolPath = $SysvolPath } }
        
        Install-ADDSForest @params -SkipPreChecks   
    }
}

function New-ADDSDomainController()
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)][securestring]$SafeModeAdministratorPassword,
        [Parameter(Mandatory = $true)][securestring]$AdministratorCredentials,
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $false)][string]$DomainNetbiosName,
        [Parameter(Mandatory = $false)][string]$DatabasePath, 
        [Parameter(Mandatory = $false)][string]$LogPath,
        [Parameter(Mandatory = $false)][string]$SysvolPath
    )

    Process
    {
        $WindowsFeatures = "AD-Domain-Services", "DNS", "gpmc"
        foreach ($WindowsFeature in $WindowsFeatures)
        {
            if (-not (Get-WindowsFeature $WindowsFeatures -ErrorAction stop))
            {
                Write-Error -Message ("Missing requried role - {0}" -f $WindowsFeature)
                Return $Null
            }
        }
        
        try 
        {
            $params = @{
                DomainMode                    = $DomainMode
                ForestMode                    = $ForestMode
                SafeModeAdministratorPassword = $SafeModeAdministratorPassword
                InstallDns                    = $true
                NoRebootOnCompletion          = $false
                CreateDnsDelegation           = $false
                DomainName                    = $DomainName
                DomainNetbiosName             = $DomainNetbiosName
                Force                         = $true
                Credential                    = $AdministratorCredentials
            }
    
            if ($DatabasePath) { $params += @{DatabasePath = $DatabasePath } }
            if ($LogPath) { $params += @{LogPath = $LogPath } }
            if ($SysvolPath) { $params += @{SysvolPath = $SysvolPath } }
            
            Install-ADDSDomainController @params -ErrorAction stop
        }
        catch 
        {
            Write-Error $_.Exception.Message
            Return $null
        }
    }
}

Function New-ADDSOUStructure()
{
    [CmdletBinding()]
    param()
    
    process 
    {
        try 
        {
            $DomainDN = (Get-ADDomain).distinguishedname 
            Write-Output "Create Enterprise Organizational Unit"
            $EnterpriseOUs = @(
                @{Name = "ENT"; path = $DomainDN }
                @{Name = "Groups"; path = "OU=ENT,$DomainDN" }
                @{Name = "Servers"; path = "OU=ENT,$DomainDN" }
                @{Name = "Users"; path = "OU=ENT,$DomainDN" }
                @{Name = "Sensitive Objects"; path = "OU=ENT,$DomainDN" }
                @{Name = "Users"; path = "OU=Sensitive Objects,OU=ENT,$DomainDN" }
                @{Name = "Groups"; path = "OU=Sensitive Objects,OU=ENT,$DomainDN" }
                @{Name = "Managed"; Path = $DomainDN }
                @{Name = "Users"; Path = "OU=Managed,$DomainDN" }
                @{Name = "Employees"; Path = "OU=Users,OU=Managed,$DomainDN" }
                @{Name = "Students"; Path = "OU=Users,OU=Managed,$DomainDN" }
                @{Name = "Inactive"; Path = "OU=Users,OU=Managed,$DomainDN" }
                @{Name = "Groups"; Path = "OU=Managed,$DomainDN" }
                @{Name = "Delegation"; Path = "OU=Groups,OU=Managed,$DomainDN" }
            )
            
            
            foreach ($EnterpriseOU in $EnterpriseOUs)
            {
                $OuDn = "OU=$($EnterpriseOU.Name),$($EnterpriseOU.Path)"
                $OuExists = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $OuDn }
                if (-not ($OuExists))
                {
                    Write-Output "Creating $OuDn"
                    New-ADOrganizationalUnit -Name $EnterpriseOU.Name -path $EnterpriseOU.Path -ErrorAction Stop 
                }
                else 
                {
                    Write-Output "$OuDn Already exists"
                }
            }
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return $null
        }
    }
}

function Set-ADDSOuAcls()
{
    [CmdletBinding()]
    param()

    Process 
    {
        try 
        {
            $DomainDN = $(Get-ADDomain).distinguishedName
            $DomainName = $(Get-ADDomain).Name
            $sdholder = $(Get-adobject "CN=AdminSDHolder,CN=System,$((Get-ADDomain).distinguishedName)").DistinguishedName
            $ENTOU = "ou=sensitive objects,ou=ent,$DomainDN"
            $ManOU = "ou=Managed,$DomainDN"
            
            dsacls $sdholder /I:T /R "NT AUTHORITY\Authenticated Users"
            dsacls $sdholder /I:T /G "NT AUTHORITY\Authenticated Users:RCRP"
    
            $ENTOUExists = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ENTOU }
            if (-not ($ENTOUExists))
            {
                dsacls $ENTOU /P:Y
                dsacls $ENTOU /I:T /R "NT AUTHORITY\Authenticated Users"
                dsacls $ENTOU /I:T /R "SYSTEM"
                dsacls $ENTOU /I:T /R "Account Operators"
                dsacls $ENTOU /I:T /R "Print Operators"
                dsacls $ENTOU /I:T /G "$DomainName\Enterprise Admins:GA" 
                dsacls $ENTOU /I:T /G "$DomainName\Domain Admins:GA" 
                dsacls $ENTOU /I:T /G "Administrators:GA" 
                dsacls $ENTOU /I:S /G "Pre-Windows 2000 Compatible Access:LCRCRP"
                dsacls $ENTOU /I:T /G "ENTERPRISE DOMAIN CONTROLLERS:RP"
            }
            $ManOUExists = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ENTOU }
            if (-not ($ManOUExists))
            {
                dsacls $ManOU /P:Y
                dsacls $ManOU /I:T /R "NT AUTHORITY\Authenticated Users"
                dsacls $ManOU /I:T /G "NT AUTHORITY\Authenticated Users:RCRP"
            }   
        }
        catch 
        {
            Write-Host
            Return
        }
    }
}

function Move-ADDSSensitiveObjects()
{
    [CmdletBinding()]
    param()
    
    process 
    {
        try 
        {
            $DomainDN = $(Get-ADDomain).distinguishedName
            $SObjects = @(
                "Domain Admins"
                "Enterprise Admins"
                "Group Policy Creator Owners"
                "Schema Admins"
                "Administrator"
            )
            
            Foreach ($SObject in $SObjects)
            {
                $object = get-adobject -filter { name -eq $SObject } -pr objectclass
                If ($Object)
                {
                    If ($Object.ObjectClass -eq "Group")
                    {
                        Move-ADObject $Object.DistinguishedName -TargetPath "ou=groups,ou=sensitive objects,ou=ent,$DomainDN" -Verbose
                    }
                    Else
                    {
                        Move-ADObject $Object.DistinguishedName -TargetPath "ou=users,ou=sensitive objects,ou=ent,$DomainDN" -Verbose
                    }
                }
            }
        }
        catch 
        {
            Write-Error $_.Exception.Message
            Return $null
        }
    }

}

function Set-ADDSDirectoryServices()
{
    [CmdletBinding()]
    param()
    
    process 
    {
        try 
        {
            $dSHeuristics = "CN=Directory Service,CN=Windows NT,CN=Services,cn=Configuration,$((Get-ADDomain).distinguishedName)"
            if ((Get-ADForest).rootdomain -eq (get-ADdomain).dnsroot)
            {
                $CurrentValue = (Get-ADObject -identity $dSHeuristics -pr dSHeuristics -ErrorAction SilentlyContinue).dSHeuristics
                $Value = "001000000"
        
                If ($CurrentValue)
                {
                    If ($CurrentValue -ne $Value)
                    {
                        Write-Host "dSHeuristics has been set to $CurrentValue"
                        Set-ADObject "$dSHeuristics" -replace @{dsHeuristics = $Value } -PassThru
                    }
                    Else
                    {
                        Write-Host "dSHeuristics is already set to $Value"
                    }
                }
                Else
                {
                    Set-ADObject "$dSHeuristics" -add @{dsHeuristics = $Value } -PassThru
                    Write-Host "dSHeuristics has been set to $Value"
                }
            }

            $MachineAccount = "$((Get-ADDomain).distinguishedName)"
            $CurrentValue = (Get-ADObject -identity $MachineAccount -pr ms-DS-MachineAccountQuota)."ms-DS-MachineAccountQuota"
        
            If ($CurrentValue -ne 0)
            {
                Write-Host "Ms-Ds-MachineAccountQuota is set to $CurrentValue"
                Set-ADObject "$MachineAccount" -replace @{"Ms-Ds-MachineAccountQuota" = 0 } -PassThru
            }
            Else
            {
                Write-Host "Ms-Ds-MachineAccountQuota is configured correctly"
            }
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return
        }
        
    }
}

function Set-DNSServerScavenging()
{
    [CmdletBinding()]
    param()
    
    process 
    {
        try 
        {
            Write-Output "Setting DNS Server Scavenging Settings"
            Set-DnsServerScavenging `
                -ScavengingInterval 3.00:00:00 `
                -NoRefreshInterval 3.00:00:00 `
                -RefreshInterval 3.00:00:00 `
                -ApplyOnAllZones `
    
            Write-Output "Setting DNS Zone Scavenging Settings"
            Get-DnsServerZone | Where-Object { $_.isAutoCreated -eq $false } | Set-DnsServerZoneAging `
                -Aging $true `
                -NoRefreshInterval 3.00:00:00 `
                -RefreshInterval 3.00:00:00 `
        
        }
        catch
        {
            Write-Error $_.Exception.Message
        }
    }
}

function Disable-DNSServerRecursion()
{
    [CmdletBinding()]
    param()
    
    process 
    {
        try 
        {
            $DnsServerRecursion = Get-DnsServerRecursion | Select-Object -ExpandProperty Enable
            if ($DnsServerRecursion -eq $false)
            {
                Write-Host "DNS Server Recursion already disabled"
                Return
            }
            
            Set-DnsServerRecursion -Enable $false -ErrorAction Stop
            Write-Output "DNS Server Recursion has been disabled"
        }
        catch
        {
            Write-Error $_.Exception.Message
            Return
        }
    }
}