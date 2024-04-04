function Set-ServerKms()
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