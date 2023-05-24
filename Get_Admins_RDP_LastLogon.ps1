# Last logon EventID = 5379
$eventID = 5379
$hostname = hostname
$GroupAdm = 'Administrators'
$GroupRDS = 'Remote Desktop Users'
$Path = '.\'

$AdmMembers = Get-LocalGroupMember -Group $GroupAdm
$RDSMembers = Get-LocalGroupMember -Group $GroupRDS

#Split Domain and user "DOMAIN\username"
$admins = @()
foreach($a in $AdmMembers){
    $a = ($a -Split '\\')[1]
    $admObj = [PSCustomObject]@{
        "Username" = $a
        "Group" = $GroupAdm
    }
    $admins += $admObj
}

#Split Domain and user "DOMAIN\username" and get username
$RDS = @()
foreach($r in $RDSMembers){
    $r = ($r -Split '\\')[1]
    
    $rdsObj = [PSCustomObject]@{
        "Username" = $r
        "Group" = $GroupRDS
    }
$RDS += $rdsObj
}
$allusers = $admins + $rds | Group-Object username

$Result = @()

foreach($i in $allusers){

    $events = Get-EventLog -LogName 'Security' -source microsoft-windows-security-auditing -InstanceId $eventID |
        Where-Object {($_.replacementstrings[1] -eq $i.Name)} |
        Select-Object `
            @{Label='UserName';Expression={$_.replacementstrings[1]}},
            @{Label='Time';Expression={$_.TimeGenerated.ToString('g')}} -First 1
    
    $allObj = [PSCustomObject]@{
        "Hostname" = $hostname
        "Account" = $i.Name
        "LastLogon" = $events.Time
        "Member" = $i.Group.Group -join ','
    }
    $Result += $allObj
}

$Result | Export-csv -Path "$Path\$hostname-report.csv" -NoTypeInformation -Delimiter ";"
