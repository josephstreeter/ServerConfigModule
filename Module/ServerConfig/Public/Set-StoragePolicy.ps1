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