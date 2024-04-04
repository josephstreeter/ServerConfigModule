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