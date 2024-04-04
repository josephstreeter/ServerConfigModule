Function Enable-RemoteAccessWinRm()
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