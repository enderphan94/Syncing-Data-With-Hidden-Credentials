param(
    [string]$scriptPath ="C:\Temp\BO\",
    [string]$BOData = $scriptPath + "BORawData.csv",
    [string]$serviceAccountName = "STM\8wph",
    [string]$server = "kubertu.se",
    [string]$zabbix_url= $null,
    [string]$targetHost = "srv68.f.myt.se"
)

#################################
#                               #
# setting up Logs and Password  #
#                               #
#################################
$logsPath = $scriptPath + "logs"
$date = (get-date).ToString('yyyy-MM-dd')
$dateLogTime= "[" + ( get-date ).ToString('yyyy-MM-dd HH:mm:ss') + "]: "
if( -Not (Test-Path $logsPath) ){
    New-Item -ItemType directory -Path $logsPath
}

if(!(Test-Path $BOData)){
    $errorMessage = "$BOData not found"
    Write-Output $errorMessage
    writeLog $($dateLogTime + $errorMessage) -type "error"
    exit
}
$passwordFile = $scriptPath +"password.txt"
if(-not(Test-Path $passwordFile)){
    read-host "Service account's password" -assecurestring | convertfrom-securestring | out-file $passwordFile
}

Function writeLog($log,$type){     
     
    if($type -eq "info"){
        $logFile= $logsPath + "\infor_log_" + $date + ".txt"
    }
    if($type -eq "error"){
        $logFile= $logsPath + "\error_log_" + $date + ".txt"
    }
    if($type -eq "monitor"){
        $logFile= $logsPath + "\monitor_log_" + $date + ".txt"
    }

    if( -Not (Test-Path $logFile))
    {
      New-Item -ItemType file $logFile
    }
    add-content $logFile "$log`n"
}

# add Zabbix_url in prod.
if(!$scriptPath -or !$BOData -or !$serviceAccountName -or !$server  -or !$targetHost){
    $errorMessage = "Parameter is missing, script stops running"
    Write-Output $errorMessage
    writeLog $($dateLogTime + $errorMessage) -type "error"
    exit
}

if((Test-Connection evdetect.sbcore.net -Quiet ) -eq $false){
    $errorMessage = "Cannot connect to Zabbix Server"
    Write-Output $errorMessage
    writeLog $($dateLogTime + $errorMessage) -type "error"
    exit
}
#################################
#                               #
#         Monitoring            #
#                               #
#################################

function TrustCert{
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type)
{
    TrustCert
}

function send-zabbix {

    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetHost,
        [Parameter(Mandatory=$true)]
        $data,
        [Parameter(Mandatory=$false)]
        [string]$Url
    ) 
    $body = ($data.Keys | % { @{host=$TargetHost; key=$_ ; value=$data[$_]} } | ConvertTo-Json)

    if (!$Url) {
        Write-Host "Zabbix API endpoint not specified...`n$($body | Out-String)"
        return
    }

    try {
        Invoke-WebRequest -Uri $Url -Method POST -Body $body
        $informationMessage = "The data has been sent to Zabbix"
        writeLog $($dateLogTime+$informationMessage) -type "monitor"
    } catch [exception] {
        $Host.UI.WriteErrorLine("ERROR: $($_.Exception.Message)")
        $errorMessage = "The data has NOT been sent to Zabbix"
        writeLog $($dateLogTime+$errorMessage) -type "monitor"
    }
}

function getGroupsDesciption{
    param($groupName)
    $description = Get-ADGroup -Identity $groupName -Properties * -Server $server|select Description
    if($description.description -eq $null){
        return $null
    }
    #$description = $description.description -replace "Rights to view" -replace "in Business Objects" -replace '(^\s+|\s+$)',''
    return $description.description -replace "Rights to view" -replace "in Business Objects" -replace '(^\s+|\s+$)',''
}

function getGroupsOwner{
    param($groupName)
    $owner = Get-ADGroup -Identity $groupName -Properties * -Server $server|select ManagedBy
    if($owner.ManagedBy -eq $null){
        return $null
    }
    return $owner.ManagedBy -replace '^CN=(.+?),(?:CN|OU).+','$1'
}

function monitoring{
    $groups = @{} 
    foreach ($g in $(Get-ADgroup -Filter {Name -like "USG.BB.APP BO_DATA_*"} -Properties * -Server $server)) {
        $groups.Add($g.Name, $g.Description)
    }

    $folders = Import-CSV $BOData -Header ("ID", "Name", "Owner", "ServiceID") | Sort-Object Name
    
    $xgroups = @{} + $groups
    
    $folderrOnwerMissing = @()
    $folderNameChanged = @()
    $folderOwnerChanged = @()
    $folderOwnderUpdated = @()
    $folderNoMapped = @()
   
    foreach ($f in $folders) {

        $outf = New-Object PSObject -Property @{Name=$f.Name; Owner=$f.Owner; Id=$f.ID; ServiceID=$f.ServiceID; Group=""}
    
        if ($f.Name -match "^[0-9]{3}(|\.[0-9]{2})\ " -or $f.Name -match "^[0-9]"){
            $prefix = ($f.Name -Split " ")[0]
            # Find the corresponding Groups in AD
            $key = @($xgroups.Keys -imatch ("^USG.BB.APP BO_DATA_{0}_" -f $prefix))
                       
            if ($key.count -eq 1) {
                $name = $key[0] 
                $outf.Group = $name
                $xgroups.Remove($name)    
                                       
                # Folder is missing owner
                if($f.Owner -eq ""){ 
                    $folderrOnwerMissing += $f.name
                }

                # Folder name has changed
                $foulderNameString = $f.name -replace '(^\s+|\s+$)',''
                if($(getGroupsDesciption -groupName $name) -ne $foulderNameString){
                     $folderNameChanged += $f.name
                }

                # Owner has changed             
                if($f.Owner -ne "" -and $(getGroupsOwner -groupName $name) -ne $null -and $(getGroupsOwner -groupName $name) -ne $f.Owner){
                    $folderOwnerChanged += $f.name     
                }

                # Folder has onwer updated                
                if($f.Owner -ne "" -and $(getGroupsOwner -groupName $name) -eq $null -and $(getGroupsOwner -groupName $name) -ne $f.Owner){                 
                   $folderOwnderUpdated += $f.name     
                }
            }
            else { #Folder has no corresponding groups in AD
               $folderNoMapped += $f.Name      
            }           
        }        
    }

    return @{
        "folder-owner-missing" = ($folderrOnwerMissing|sort) -join ", "
        "folder-name-changed" = ($folderNameChanged|sort) -join ", "
        "folder-owner-changed" = ($folderOwnerChanged|sort) -join ", "
        "folder-owner-update" = ($folderOwnderUpdated|sort) -join ", "
        "folder-no-mapped" = ($folderNoMapped|sort) -join ", "
    }    
}
#monitoring
send-zabbix -TargetHost $targetHost -Data $(monitoring) -Url $zabbix_url

#################################
#                               #
#         Sync                  #
#                               #
#################################
function cred{
       
    $password = Get-Content $passwordFile |ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $serviceAccountName, $password

    return $cred
}

function ownerMissing{
    param($add)

    $getOwnerMissing += $add

    return $getOwnerMissing
}

function ownerUpdate{

    param($groupName,$owner,$cred)

    Set-ADGroup -Identity $groupName -ManagedBy $owner -Server $server -Credential $cred
}

function descriptionUpdate{

    param($groupName,$folderName,$cred)
    
    Set-ADGroup -Identity $groupName -Description "Rights to view $folderName in Business Objects" -Server $server -Credential $cred
   
}

function notesUpdate{

    param($groupName,$folderName,$cred)

    $currentNotes = Get-ADGroup -Identity $groupName -Properties * -Server $server |select -ExpandProperty info
    
    if($currentNotes -ne $folderName){
        Set-ADGroup -Identity $groupName -Clear info -Server $server -Credential $cred
        Set-ADGroup -Identity $groupName -Add @{info=$folderName} -Server $server -Credential $cred
    }
    Set-ADGroup -Identity $groupName -Add @{info=$folderName} -Server $server -Credential $cred    
}

function msOrgGroupSubtypeNameSetandUpdate{

    param($groupName,$serviceID,$cred)

    $currentGroupSubtypeName = Get-ADGroup -Identity $groupName -Properties * -Server $server |select -ExpandProperty msOrg-GroupSubtypeName

    if($currentGroupSubtypeName -ne $serviceID){
        Set-ADGroup -Identity $groupName -Clear msOrg-GroupSubtypeName -Server $server -Credential $cred
        Set-ADGroup -Identity $groupName -Add @{'msOrg-GroupSubtypeName'=$serviceID} -Server $server -Credential $cred
    }
    Set-ADGroup -Identity $groupName -Add @{'msOrg-GroupSubtypeName'=$serviceID} -Server $server -Credential $cred
}

function sync{ # sync data if it matches

    param($groupName,$folderName,$owner,$serviceID)
    $cred = cred
    try{
        ownerUpdate -groupName $groupName -owner $owner -cred $cred
        descriptionUpdate -groupName $groupName -folderName $folderName -cred $cred
        notesUpdate -groupName $groupName -folderName $folderName -cred $cred
        msOrgGroupSubtypeNameSetandUpdate -groupName $groupName -serviceID $serviceID -cred $cred

        $informationMessage = "$groupName has been synced successfully"
        writeLog $($dateLogTime +$informationMessage) -type "info"
    }
    catch{
        $errorMessage = "$groupName has been synced unsuccessfully"
        writeLog $($dateLogTime + $errorMessage) -type "error"
    }

}

function cleanIfNotMatch{ # Clear Info and ManagedBy if not match
    param($groupName,$type)
    $cred = cred
    try{
        Set-ADGroup -Identity $groupName -Clear info -Server $server -Credential $cred
        Set-ADGroup -Identity $groupName -Clear ManagedBy -Server $server -Credential $cred

        if($type -eq "owner"){
            $informationMessage = "$groupName missing owner has been mapped successfully"
        }
        else{
            $informationMessage = "$groupName has no corressponding folder has been cleaned up successfully"
        }
        writeLog $($dateLogTime +$informationMessage) -type "info"
    }
    catch{
        $errorMessage = "$groupName has not been cleaned unsuccessfully"
        writeLog $($dateLogTime + $errorMessage) -type "error"
    }
}

function matchNumberGroup{ # mapping groups and folders with Number prefix
    $groups = @{} 
    foreach ($g in $(Get-ADgroup -Filter {Name -like "USG.BB.APP BO_DATA_*"} -Properties * -Server $server)) {
        $groups.Add($g.Name, $g.Description)
    }

    $folders = Import-CSV $BOData -Header ("ID", "Name", "Owner", "ServiceID") | Sort-Object Name
    
    $xgroups = @{} + $groups
    
    $OUT = @()
   
    foreach ($f in $folders) {
        $outf = New-Object PSObject -Property @{Name=$f.Name; Owner=$f.Owner; Id=$f.ID; ServiceID=$f.ServiceID; Group=""}
    
        if ($f.Name -match "^[0-9]{3}(|\.[0-9]{2})\ " -or $f.Name -match "^[0-9]"){
            $prefix = ($f.Name -Split " ")[0]
            # Find the corresponding Groups in AD
            $keys = @($xgroups.Keys -imatch ("^USG.BB.APP BO_DATA_{0}_" -f $prefix))            
            if ($keys.count -eq 1) {
                $name = $keys[0] 
                $outf.Group = $name
                $xgroups.Remove($name)                           
                sync -groupName $name -folderName $f.Name -owner $f.owner -serviceID $f.ServiceID

                if($f.Owner -eq ""){
                    cleanIfNotMatch -groupName $name -type "owner"
                }
            }
        }
        else{            
            foreach($groupName in $xgroups.Keys){
                cleanIfNotMatch -groupName $groupName -type "xgroup"
            }
        }
        
    }    
}

function matchStringGroup{ # exceptional case with no naming convention matcher

    $LMSGroupName= Get-ADgroup -Filter {Name -like "USG.BB.APP BO_DATA_LMS"} -Properties * -Server $server|select -ExpandProperty Name

    $folders = Import-CSV $BOData -Header ("ID", "Name", "Owner", "ServiceID") | Sort-Object Name
      
    $OUT = @()
    
    foreach ($f in $folders) {
        $outf = New-Object PSObject -Property @{Name=$f.Name; Owner=$f.Owner; Id=$f.ID; ServiceID=$f.ServiceID; Group=""}       
        if ($f.Name -eq "Liquidity/ILM"){
            $name = $LMSGroupName 
            $outf.Group = $name                          
            sync -groupName $name -folderName $f.Name -owner $f.owner -serviceID $f.ServiceID       
        }        
    }     
}

function main{

    $folders = Import-CSV $BOData -Header ("ID", "Name", "Owner", "ServiceID") | Sort-Object Name
    $ownerExist = $true

    foreach($folder in $folders){   
        
        if($folder.Owner -ne ""){  
            try{
                Get-ADUser -Identity $folder.Owner -Server $server -ErrorAction stop|Out-Null
            }
            catch{
                $ownerExist = $false
                $errorMessage = $folder.Owner + " does not exist, script stops here"
                Write-Error $errorMessage # for test only                
                writeLog $($dateLogTime + $errorMessage) -type "error"
                exit
            }   
        }
    }

    if($ownerExist -eq $true){
        matchNumberGroup
        matchStringGroup
        Write-host "`nSyncing process has been done" -BackgroundColor Green
    }
    
}
main
