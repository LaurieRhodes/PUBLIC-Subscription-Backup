﻿[CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [string]$githistorydir,
        [Parameter(mandatory=$true)]
        [string]$reportdir,
        [Parameter(mandatory=$true)]
        [string]$backupdir,
        [Parameter(mandatory=$true)]
        [string]$moduledir
    )



<#

Purpose is to generate .md files for the report Index

#>
#$DebugPreference = 'Continue'

Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug

if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}
if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}


$files = Get-ChildItem "$($githistorydir)" -Filter "README.md" -Recurse -Depth 1

#The output of the Index will be the root folder
$outputpath = "$($githistorydir)"

# Make sure the output directory exists
New-Item -ItemType Directory -Force -Path $outputpath

# Create a Report object class to contain all the harvested fields that interest me.
# this will allow results to be sorted before being written to file

Class oResult{
    [String]$ReportName
    [String]$Path
    [String]$IsModified
}

# Init Output Array
$OutputArray =@()

 # Populate the content

# Recurse through all objects
for ($i=0; $i -lt $files.Count; $i++) {

    # Get the first line of each README file
     $otemplate = Get-Content -Path $files[$i].FullName


     $otemp = New-Object oResult

     # First heading line of each MD file is the title of the report
     $Reportname = $otemplate -match "# "
     $Reportname = $Reportname.Replace('#','')
     $Reportname = $Reportname.Trim()
     $otemp.ReportName = $Reportname.Replace('x','')

     # Path variable needs to be a relative path
     $relativepath = ($files[$i].FullName).Substring( $githistorydir.Length +1 ,(($files[$i].FullName).Length - ($githistorydir.Length +1)))
     $otemp.Path = $relativepath

     #  // TODO Git diff
     # $otemp.IsModified

     # Don't create a circular link to the root report
     if ($otemp.Path -ne "README.md"){
        $OutputArray += $otemp
      }

}

#  Sort the output

$OutputArray  = $OutputArray  | sort-object  -Property ReportName



# Create the MD Header

$header =@"
![](..$($slash)reports$($slash)img$($slash)header.jpg)

# Reports




| Report                      | Path                |Is Modified |
| --------------------------- | ------------------- |----------- |
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Force -InputObject $header


$OutputArray | ForEach-Object {


  "| $($_.ReportName)     | [$($_.Path)]($($_.Path))        | $($_.IsModified )         |" | out-file -FilePath "$($outputpath)$($slash)README.md"  -Append

}


$footer = @"

![](..$($slash)reports$($slash)img$($slash)logo.jpg)
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Append -InputObject $footer