function Enable-RemoteAccessOpenSsh()
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