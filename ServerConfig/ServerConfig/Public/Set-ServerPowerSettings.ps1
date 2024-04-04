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