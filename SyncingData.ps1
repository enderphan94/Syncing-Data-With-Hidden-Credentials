
function ownerUpdate{

    param($groupName,$owner,$cred)

    Set-ADGroup -Identity $groupName -ManagedBy $owner -Server abd.com -Credential $cred
}

function descriptionUpdate{

    param($groupName,$folderName,$cred)
    
    Set-ADGroup -Identity $groupName -Description "Rights to view $folderName in Business Objects" -Server abd.com -Credential $cred
   
}

function notesUpdate{

    param($groupName,$folderName,$cred)

    $currentNotes = Get-ADGroup -Identity $groupName -Properties * -Server abd.com |select -ExpandProperty info
    
    if($currentNotes -ne $folderName){
        Set-ADGroup -Identity $groupName -Clear info -Server abd.com -Credential $cred
        Set-ADGroup -Identity $groupName -Add @{info=$folderName} -Server abd.com -Credential $cred
    }
    
    Set-ADGroup -Identity $groupName -Add @{info=$folderName} -Server abd.com -Credential $cred

}

# Password saved: read-host -assecurestring | convertfrom-securestring | out-file C:\Users\p998wph\Documents\Ender4\password.txt
function cred{

    $username = "abd.com\p998"
    $password = Get-Content "C:\Users\p998\Documents\Ender4\password.txt" |ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password

    return $cred
}

function sync{

    param($groupName,$folderName,$owner)

    $cred = cred
    ownerUpdate -groupName $groupName -owner $owner -cred $cred
    descriptionUpdate -groupName $groupName -folderName $folderName -cred $cred
    notesUpdate -groupName $groupName -folderName $folderName -cred $cred
}

function main{

    $groups = @{} 
    foreach ($g in $(Get-ADgroup -Filter {Name -like "BO_DATA_*"} -Properties * -Server abd.com)) {
        $groups.Add($g.Name, $g.Description)
    }

    $folders = Import-CSV "BORawData.csv" -Header ("ID", "Name", "Owner", "ServiceID") | Sort-Object Name
    
    $xgroups = @{} + $groups
    
    $OUT = @()
    
    foreach ($f in $folders) {
        $outf = New-Object PSObject -Property @{Name=$f.Name; Owner=$f.Owner; Id=$f.ID; ServiceID=$f.ServiceID; Group=""}
       
        if ($f.Name -match "^[0-9]{3}(|\.[0-9]{2})\ " -or $f.Name -match "^[0-9]"){
            $prefix = ($f.Name -Split " ")[0]
            # Find the corresponding Groups in AD
            $keys = @($xgroups.Keys -imatch ("^BO_DATA_{0}_" -f $prefix))
        
            if ($keys.count -eq 1) {
                $name = $keys[0] 
                $outf.Group = $name
                $xgroups.Remove($name)                
                sync -groupName $name -folderName $f.Name -owner $f.owner
            }
        }        
    }     
}
main