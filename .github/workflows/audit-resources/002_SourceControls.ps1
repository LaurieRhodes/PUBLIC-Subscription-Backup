﻿[CmdletBinding()]
    param(
        #[Parameter(mandatory=$false)]
        #[string]$reportdir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\reports",
        #[Parameter(mandatory=$false)]
        #[string]$backupdir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\json",
        #[Parameter(mandatory=$false)]
        #[string]$moduledir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\.github\workflows\modules",
        [Parameter(mandatory=$false)]
        [psobject]$Filelist,      
        [Parameter(mandatory=$true)]
        [string]$reportdir,
        [Parameter(mandatory=$true)]
        [string]$backupdir,
        [Parameter(mandatory=$true)]
        [string]$moduledir             
    )


<#

Purpose is to generate .md files for Device\Configurations

#>
#$DebugPreference = 'Continue'

$ObjectType = "Microsoft.SecurityInsights/SourceControls"
$Friendlyname = "Source Controls"

if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}

if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}


Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug

write-debug "Running Script $Friendlyname"


$outputpath = "$($reportdir)$($slash)$(($ObjectType.Replace('/','-')).Replace('.','-'))"
write-debug "Establishing Output Path $($outputpath)"

# If a filelist hasn't been passed - create one
if ( !($Filelist) ){
$Filepathlist =  Get-ChildItem $backupdir -Filter "*.json" -Recurse | % { $_.FullName }

Class oAZObject{
    [String]$type
    [String]$path
}

# Init Output Array
$Filelist =@()

foreach ($file in $Filepathlist){

  $jsonobject = Get-Jsonfile -Path $file

     $otemp = New-Object oAZObject 
     $otemp.type = $jsonobject.type
     $otemp.path = $file

     $Filelist += $otemp

}
}

# Make sure old reports don't exist
if (Test-Path $outputpath) {
  Remove-Item $outputpath -Recurse -Force
}

# Make sure the output directory exists
 $null = New-Item -ItemType Directory -Force -Path $outputpath



# Create a Report object class to contain all the harvested fields that interest me.
# This will be unique with each report
# this will allow results to be sorted before being written to file

Class oResult{
    [String]$displayName   
    [String]$Name
    [String]$ResourceGroup
    [String]$url
}



# Init Output Array
$OutputArray =@()


# Recurse through the file list index and open all of those of our desired type
foreach($file in $FileList){

 # Select the desired object type
 if ($file.Type -eq $ObjectType){

    
     $otemplate = Get-Content -Raw -Path  $file.Path | ConvertFrom-Json 

     $otemp = New-Object oResult 
     $otemp.DisplayName = $otemplate.properties.DisplayName
     $otemp.Name = $otemplate.Name
     $otemp.ResourceGroup = ($otemplate.id).split('/')[4]
     $otemp.url = $otemplate.properties.repository.url


     $OutputArray += $otemp

      $null = New-Item -ItemType Directory -Force -Path "$($outputpath)$($slash)$($otemp.ResourceGroup)-$($otemp.Name)"


     # Create YAML copies of the Config Files
       "# $($otemplate.name)`r`n" | out-file -FilePath "$($outputpath)$($slash)$($otemp.ResourceGroup)-$($otemp.Name)$($slash)README.md" -Force
       '```' | out-file -FilePath "$($outputpath)$($slash)$($otemp.ResourceGroup)-$($otemp.Name)$($slash)README.md" -Append
       ConvertTo-Yaml -inputObject   $otemplate | out-file -FilePath "$($outputpath)$($slash)$($otemp.ResourceGroup)-$($otemp.Name)$($slash)README.md" -Append 
      # ConvertTo-Yaml -inputObject   $otemplate | write-debug
       '```' | out-file -FilePath "$($outputpath)$($slash)$($otemp.ResourceGroup)-$($otemp.Name)$($slash)README.md" -Append



 }
}


# Sort the output
$OutputArray  = $OutputArray  | sort-object  -Property DisplayName



# Create the MD Header

$header =@"
![](..$($slash)img$($slash)header.jpg)

# $($FriendlyName)


| DisplayName          | Name                              | Resource Group           |URL               |
| ---------------------| --------------------------------- | -------------------------|-------------------------|
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Force -InputObject $header


$OutputArray | ForEach-Object {

  "| [$($_.Displayname)]($($_.ResourceGroup)-$($_.name)$($slash)README.md)      | $($_.Name )     | $($_.ResourceGroup )   | $($_.url )   |" | out-file -FilePath "$($outputpath)$($slash)README.md"  -Append 
} 


$footer = @"

![](..$($slash)img$($slash)logo.jpg)
"@  

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Append -InputObject $footer


