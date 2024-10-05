#! /bin/pwsh

<#

    Purpose:  Exports key objects from Graph to a local directory

#>

#$DebugPreference = 'Continue'


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


Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug



# Clean the contents of the Backup folder
if ($BackupDir){

#Remove-Item $BackupDir$slash* -Recurse -Force


<#
if($OS -eq 'win' ){ Remove-Item $BackupDir\* -Recurse -Force }
if($OS -eq 'linux' ){

#

$foldersToDel = Get-ChildItem $BackupDir -Directory
$foldersToDel

$ExcludeFolders=@(".git",".github")

foreach ($folder in $foldersToDel){

    if ($ExcludeFolders.Contains($folder.Name ) ){write-output "Folder Name in Exclude list = $($folder.Name)"}else{
      $folder | remove-item -force -Recurse
    }
}

#>
}


# All auditing will be run through separate audit modules




$files     = Get-ChildItem "$($ScriptDir)$($Slash)audit-resources" -Filter "*.ps1"

write-debug "$($ScriptDir)$($Slash)audit-resources"



# If a filelist hasn't been passed - create one

#$Filelist = Get-FileList -directory $backupdir



for ($i=0; $i -lt $files.Count; $i++) {


write-debug "$($files[$i].FullName)"

$response =  invoke-expression -Command "$($files[$i].FullName) -reportdir $($ReportDir) -backupdir $($BackupDir) -moduledir $($ModuleDir) "

write-debug "response = $response"

}






