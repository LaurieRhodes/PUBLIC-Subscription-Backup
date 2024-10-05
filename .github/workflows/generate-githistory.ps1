#! /bin/pwsh

<#

    Purpose:  Exports key objects from Graph to a local directory

#>

#$DebugPreference = 'Continue'


$rootDir   = "C:\Users\Laurie\Documents\GitHub\git-history"
if ($($env:DIRECTORY)){$rootDir   = $($env:DIRECTORY)}



#$ScriptDir     = Split-Path $script:MyInvocation.MyCommand.Path

# Determine if script is being run on linux or windows by the direction
# of slashed in the PATH statement
if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}




$ScriptDir     = Split-Path $script:MyInvocation.MyCommand.Path

# Create a slash variable based on the OS type of the host
if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}


 $BackupDir = "$($rootDir)$($slash)json"
 $ReportDir = "$($rootDir)$($slash)reports"
 $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
 $ModuleDir = "$($ScriptDir)$($slash)modules"
 $githistorydir = "$($rootDir)$($slash)githistory"

Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug



# Clean the contents of the output folder
if ( $githistorydir){

Remove-Item  $githistorydir$slash* -Recurse -Force


}


# All auditing will be run through separate audit modules




$files     = Get-ChildItem "$($ScriptDir)$($Slash)git-history" -Filter "*.ps1"

write-debug "$($ScriptDir)$($Slash)git-history"






for ($i=0; $i -lt $files.Count; $i++) {


write-debug "$($files[$i].FullName)"

$response =  invoke-expression -Command "$($files[$i].FullName) -reportdir $($ReportDir) -backupdir $($BackupDir) -moduledir $($ModuleDir) -githistorydir $($githistorydir) "

write-debug "response = $response"

}






