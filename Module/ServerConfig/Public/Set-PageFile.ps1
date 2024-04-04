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