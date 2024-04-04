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