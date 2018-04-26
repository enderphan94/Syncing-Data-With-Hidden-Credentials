# Syncing-Data-With-Hidden-Credential

```
read-host -assecurestring | convertfrom-securestring | out-file C:\Users\p998wph\Documents\Ender4\password.txt
function cred{

    $username = "abd.com\p998"
    $password = Get-Content "C:\Users\p998\Documents\Ender4\password.txt" |ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password
    return $cred
}
```
